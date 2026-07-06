"""CLOB V2 **deposit-wallet** trading via the unified ``polymarket`` SDK, for the MCP.

Polymarket's April-2026 CLOB V2 migration (USDC.e -> pUSD, new exchange) rejects the
legacy Gnosis-Safe proxy as an order maker ("maker address not allowed, please use
the deposit wallet flow"). ``py-clob-client-v2`` cannot produce V2 deposit-wallet
orders. This module drives the supported flow: a per-owner ERC-1967 *deposit wallet*
is the maker, orders sign POLY_1271 (signature_type 3), and wallet ops are gasless via
the session's Builder API key.

The MCP calls this when a session's signature_type == 3. It's the tx-sender, so its
egress region (must be geo-allowed by Polymarket) is what matters for the geoblock.
"""
from __future__ import annotations

import hashlib
import json
import logging
import urllib.request
from decimal import Decimal, ROUND_DOWN, ROUND_UP
from threading import Lock
from typing import Any, Dict, List, Optional

logger = logging.getLogger("polymarket-api_mcp.deposit_wallet")

_DATA_API = "https://data-api.polymarket.com"


def _data_api(path: str) -> Any:
    req = urllib.request.Request(
        _DATA_API + path, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)


class DepositWalletClient:
    """Wraps the unified SDK's SecureClient for one owner key + Builder API key.
    Lazily creates the client (which deploys the deposit wallet gaslessly on first
    use) and caches it."""

    def __init__(self, *, private_key: str, builder_key: str, builder_secret: str, builder_passphrase: str) -> None:
        self._key = private_key
        self._builder = (builder_key, builder_secret, builder_passphrase)
        self._client = None
        self._wallet: Optional[str] = None

    @property
    def client(self):
        if self._client is None:
            from polymarket import SecureClient
            from polymarket.auth import BuilderApiKey

            bk = BuilderApiKey(key=self._builder[0], secret=self._builder[1], passphrase=self._builder[2])
            self._client = SecureClient.create(private_key=self._key, api_key=bk)
            self._wallet = str(self._client.wallet)
            logger.info(
                "[deposit_wallet] ready wallet=%s type=%s",
                self._wallet, getattr(self._client, "wallet_type", "?"),
            )
        return self._client

    @property
    def wallet_address(self) -> str:
        if self._wallet is None:
            _ = self.client
        return self._wallet or ""

    def _round_price_to_tick(self, token_id: str, price: float, side: str) -> float:
        """Round a protective price bound to the market's tick grid. The CLOB rejects
        a max_price/min_price with more decimals than the tick allows. BUY ceilings
        round UP, SELL floors round DOWN. Falls back to 3 dp on lookup failure."""
        try:
            from polymarket._internal.actions.orders.market_data import fetch_tick_size_sync
            tick = fetch_tick_size_sync(self.client._ctx, token_id=str(token_id))
            rounding = ROUND_UP if str(side).upper() == "BUY" else ROUND_DOWN
            q = Decimal(str(price)).quantize(tick, rounding=rounding)
            lo, hi = tick, Decimal(1) - tick
            if q < lo:
                q = lo
            elif q > hi:
                q = hi
            return float(q)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[deposit_wallet] tick-round failed (%s); using 3dp", exc)
            return round(float(price), 3)

    def create_market_order(self, token_id: str, side: str, amount: float, worst_price: Optional[float] = None) -> Dict[str, Any]:
        """BUY: amount = USDC to spend, worst_price = max price. SELL: amount = shares,
        worst_price = min price. FOK so a fill is all-or-nothing. Returns a dict shaped
        like the legacy path (success/order_id/status/error/transactionsHashes)."""
        side_u = str(side).upper()
        try:
            c = self.client
            if side_u == "BUY":
                mp = self._round_price_to_tick(token_id, worst_price, "BUY") if worst_price else 0.99
                resp = c.place_market_order(token_id=str(token_id), side="BUY", amount=str(amount), max_price=str(mp), order_type="FOK")
            else:
                mp = self._round_price_to_tick(token_id, worst_price, "SELL") if worst_price else 0.01
                resp = c.place_market_order(token_id=str(token_id), side="SELL", shares=str(amount), min_price=str(mp), order_type="FOK")
            return self._adapt(resp)
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "status": "failed", "error": str(exc)[:400]}

    @staticmethod
    def _adapt(resp: Any) -> Dict[str, Any]:
        ok = getattr(resp, "ok", None)
        oid = str(getattr(resp, "order_id", "") or "")
        status = str(getattr(resp, "status", "") or "")
        making = float(getattr(resp, "making_amount", 0) or 0)
        taking = float(getattr(resp, "taking_amount", 0) or 0)
        txs = list(getattr(resp, "transactions_hashes", ()) or ())
        if ok is False or (not oid and making <= 0 and taking <= 0):
            err = (getattr(resp, "error", None) or getattr(resp, "reason", None)
                   or getattr(resp, "message", None) or f"rejected (status={status or 'n/a'})")
            return {"success": False, "status": status or "rejected", "error": str(err)[:400]}
        filled = bool(ok) and (making > 0 or taking > 0)
        return {"success": bool(filled), "order_id": oid, "status": status or ("matched" if filled else "unmatched"),
                "transactionsHashes": txs, "making_amount": making, "taking_amount": taking}

    def cancel_order(self, order_id: str) -> Dict[str, Any]:
        try:
            return {"success": True, "result": str(self.client.cancel_order(order_id=str(order_id)))}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": str(exc)[:300]}

    def get_collateral_balance(self) -> Optional[float]:
        try:
            ba = self.client.get_balance_allowance(asset_type="COLLATERAL")
            return int(ba.balance) / 1e6
        except Exception as exc:  # noqa: BLE001
            logger.warning("[deposit_wallet] collateral balance failed: %s", exc)
            return None

    def get_token_balance(self, token_id: str) -> float:
        try:
            for p in _data_api(f"/positions?user={self.wallet_address}&sizeThreshold=0.0") or []:
                if str(p.get("asset")) == str(token_id):
                    return float(p.get("size", 0) or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[deposit_wallet] token_balance failed: %s", exc)
        return 0.0

    def get_positions(self) -> List[Dict[str, Any]]:
        try:
            d = _data_api(f"/positions?user={self.wallet_address}&sizeThreshold=0.0")
            return d if isinstance(d, list) else []
        except Exception:  # noqa: BLE001
            return []


# Cache one DepositWalletClient per owner key (reuse the SecureClient across a
# session's calls; avoids re-deploying/re-deriving on every order). Keyed by a hash
# of the key, never the key itself.
_cache: Dict[str, DepositWalletClient] = {}
_cache_lock = Lock()


def get_deposit_client(private_key: str, builder_key: str, builder_secret: str, builder_passphrase: str) -> DepositWalletClient:
    h = hashlib.sha256(private_key.encode()).hexdigest()[:16]
    with _cache_lock:
        if h not in _cache:
            _cache[h] = DepositWalletClient(
                private_key=private_key, builder_key=builder_key,
                builder_secret=builder_secret, builder_passphrase=builder_passphrase,
            )
        return _cache[h]
