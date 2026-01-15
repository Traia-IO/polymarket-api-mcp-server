#!/usr/bin/env python3
"""
Polymarket API MCP Server - FastMCP with D402 Transport Wrapper

Uses FastMCP from official MCP SDK with D402MCPTransport wrapper for HTTP 402.

Architecture:
- FastMCP for tool decorators and Context objects
- D402MCPTransport wraps the /mcp route for HTTP 402 interception
- Proper HTTP 402 status codes (not JSON-RPC wrapped)

Generated from OpenAPI: https://docs.polymarket.com/

Environment Variables:
- SERVER_ADDRESS: Payment address (IATP wallet contract)
- MCP_OPERATOR_PRIVATE_KEY: Operator signing key
- D402_TESTING_MODE: Skip facilitator (default: true)
"""

import os
import logging
import sys
import json
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
from datetime import datetime

import requests
from retry import retry
from dotenv import load_dotenv
import uvicorn

# Polymarket CLOB client for trading operations
from py_clob_client.client import ClobClient
from py_clob_client.clob_types import ApiCreds, BalanceAllowanceParams, AssetType

load_dotenv()

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('polymarket-api_mcp')

# FastMCP from official SDK
from mcp.server.fastmcp import FastMCP, Context
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# D402 payment protocol - using Starlette middleware
from traia_iatp.d402.starlette_middleware import D402PaymentMiddleware
from traia_iatp.d402.mcp_middleware import require_payment_for_tool, get_active_api_key
from traia_iatp.d402.payment_introspection import extract_payment_configs_from_mcp
from traia_iatp.d402.types import TokenAmount, TokenAsset, EIP712Domain

# Configuration
STAGE = os.getenv("STAGE", "MAINNET").upper()
PORT = int(os.getenv("PORT", "8000"))
_server_address = os.getenv("SERVER_ADDRESS")
if not _server_address:
    raise ValueError("SERVER_ADDRESS required for payment protocol")
SERVER_ADDRESS: str = _server_address  # Type assertion after validation

API_KEY = None

logger.info("="*80)
logger.info(f"Polymarket API MCP Server (FastMCP + D402 Wrapper)")
logger.info(f"API: https://gamma-api.polymarket.com")
logger.info(f"Payment: {SERVER_ADDRESS}")
logger.info("="*80)

# Create FastMCP server
mcp = FastMCP("Polymarket API MCP Server", host="0.0.0.0")

logger.info(f"✅ FastMCP server created")

# ============================================================================
# TOOL IMPLEMENTATIONS
# ============================================================================
# Tool implementations will be added here by endpoint_implementer_crew
# Each tool will use the @mcp.tool() and @require_payment_for_tool() decorators


# D402 Payment Middleware
# The HTTP 402 payment protocol middleware is already configured in the server initialization.
# It's imported from traia_iatp.d402.mcp_middleware and auto-detects configuration from:
# - PAYMENT_ADDRESS or EVM_ADDRESS: Where to receive payments
# - EVM_NETWORK: Blockchain network (default: base-sepolia)
# - DEFAULT_PRICE_USD: Price per request (default: $0.001)
# - POLYMARKET_API_API_KEY: Server's internal API key for payment mode
#
# All payment verification logic is handled by the traia_iatp.d402 module.
# No custom implementation needed!


# ============================================================================
# SESSION CREDENTIAL STORE
# ============================================================================
# Thread-safe storage for session-scoped Polymarket credentials.
# Credentials are derived once when client sends X-Polymarket-Key header
# and cached for the duration of the MCP session.

from threading import Lock

class SessionCredentialStore:
    """Thread-safe store for session-scoped Polymarket credentials."""
    
    def __init__(self):
        self._credentials: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
    
    def store(self, session_id: str, creds: ApiCreds, private_key: str) -> None:
        """Store credentials for a session."""
        with self._lock:
            self._credentials[session_id] = {"creds": creds, "key": private_key}
            logger.info(f"🔐 Stored Polymarket credentials for session {session_id[:8]}...")
    
    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get credentials for a session."""
        with self._lock:
            return self._credentials.get(session_id)
    
    def clear(self, session_id: str) -> None:
        """Clear credentials for a session."""
        with self._lock:
            if session_id in self._credentials:
                del self._credentials[session_id]
                logger.info(f"🗑️ Cleared Polymarket credentials for session {session_id[:8]}...")
    
    def has_credentials(self, session_id: str) -> bool:
        """Check if credentials exist for a session."""
        with self._lock:
            return session_id in self._credentials


# Global session store instance
session_credential_store = SessionCredentialStore()


# ============================================================================
# GEOBLOCK CHECK
# ============================================================================
# Check if Polymarket API is accessible from this region

import httpx

# Cache geoblock status (checked once on startup and cached)
_geoblock_status: Optional[Dict[str, Any]] = None
_geoblock_check_time: Optional[datetime] = None

async def check_polymarket_geoblock() -> Dict[str, Any]:
    """
    Check if Polymarket API is geoblocked from this region.
    
    Calls GET https://polymarket.com/api/geoblock to check status.
    Result is cached for 5 minutes to avoid excessive API calls.
    
    Returns:
        Dict with:
        - blocked: bool - True if geoblocked
        - country: str - Country code if available
        - message: str - Status message
        - checked_at: str - ISO timestamp
    """
    global _geoblock_status, _geoblock_check_time
    
    # Return cached result if less than 5 minutes old
    if _geoblock_status and _geoblock_check_time:
        age = (datetime.now() - _geoblock_check_time).total_seconds()
        if age < 300:  # 5 minutes
            return _geoblock_status
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get("https://polymarket.com/api/geoblock")
            data = response.json()
            
            # Polymarket returns {"blocked": true/false, "country": "XX"}
            blocked = data.get("blocked", False)
            country = data.get("country", "unknown")
            
            _geoblock_status = {
                "blocked": blocked,
                "country": country,
                "message": f"Region {'blocked' if blocked else 'allowed'}: {country}",
                "checked_at": datetime.now().isoformat()
            }
            _geoblock_check_time = datetime.now()
            
            if blocked:
                logger.warning(f"⚠️ GEOBLOCK: Polymarket API blocked from country {country}")
            else:
                logger.info(f"✅ Geoblock check passed: country {country}")
            
            return _geoblock_status
            
    except Exception as e:
        logger.error(f"❌ Geoblock check failed: {e}")
        return {
            "blocked": False,  # Assume not blocked if check fails
            "country": "unknown",
            "message": f"Check failed: {str(e)}",
            "error": str(e),
            "checked_at": datetime.now().isoformat()
        }


async def startup_geoblock_check():
    """Run geoblock check on server startup."""
    logger.info("🌍 Checking Polymarket geoblock status on startup...")
    result = await check_polymarket_geoblock()
    if result.get("blocked"):
        logger.error("="*60)
        logger.error("🚫 SERVER IS GEOBLOCKED FROM POLYMARKET!")
        logger.error(f"   Country: {result.get('country')}")
        logger.error("   Trading orders will be blocked in this region.")
        logger.error("   Consider migrating to an allowed region.")
        logger.error("="*60)
    else:
        logger.info(f"✅ Geoblock check passed: {result.get('message')}")


# ============================================================================
# POLYMARKET AUTH MIDDLEWARE
# ============================================================================
# Intercepts requests with X-Polymarket-Key header and derives/caches credentials

class PolymarketAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that handles Polymarket authentication via X-Polymarket-Key header.
    
    When a client sends X-Polymarket-Key header (containing their private key),
    this middleware:
    1. Derives Polymarket API credentials from the private key
    2. Caches them in the session store for the duration of the session
    3. All subsequent authenticated tool calls use the cached credentials
    
    This is Polymarket-specific (not in IATP library) - IATP provides generic
    additional_headers support.
    """
    
    async def dispatch(self, request: Request, call_next):
        # Check for Polymarket auth header
        polymarket_key = request.headers.get("X-Polymarket-Key")
        session_id = request.headers.get("mcp-session-id")
        
        if polymarket_key and session_id:
            # Only derive if we don't already have credentials for this session
            if not session_credential_store.has_credentials(session_id):
                try:
                    logger.info(f"🔑 Received X-Polymarket-Key for session {session_id[:8]}...")
                    creds = derive_polymarket_credentials_internal(polymarket_key)
                    session_credential_store.store(session_id, creds, polymarket_key)
                except Exception as e:
                    logger.error(f"Failed to derive Polymarket credentials: {e}")
                    # Continue with the request even if credential derivation fails
                    # The authenticated tools will return appropriate errors
        
        response = await call_next(request)
        return response


def derive_polymarket_credentials_internal(private_key: str) -> ApiCreds:
    """
    Derive Polymarket API credentials from a private key.
    
    This is used internally by the session middleware to derive and cache credentials.
    Following Polymarket docs: https://docs.polymarket.com/quickstart/first-order
    
    Uses signature_type=0 (EOA) for direct wallet trading.
    """
    try:
        from eth_account import Account
        
        # Get the funder address (the wallet address derived from the private key)
        account = Account.from_key(private_key)
        funder_address = account.address
        
        # Create a temporary client for credential derivation
        # signature_type=0 is for EOA wallets (user controls their own wallet)
        temp_client = ClobClient(
            host="https://clob.polymarket.com",
            chain_id=137,
            key=private_key,
            signature_type=0,  # EOA signature (Type 0 per Polymarket docs)
            funder=funder_address  # Funder is the EOA wallet address
        )
        
        # Use create_or_derive_api_creds as recommended by Polymarket docs
        # This creates a new key if none exists, or derives existing one
        creds = temp_client.create_or_derive_api_creds()
        
        logger.info(f"✅ Successfully derived Polymarket API credentials for {funder_address[:10]}...")
        return creds
        
    except Exception as e:
        logger.error(f"❌ Failed to derive Polymarket credentials: {e}")
        raise


def get_session_credentials(context: Context) -> Optional[Tuple[str, ApiCreds]]:
    """
    Get Polymarket credentials from session store based on the current request's session ID.
    
    Returns:
        Tuple of (private_key, ApiCreds) if credentials exist, None otherwise
    """
    try:
        # Debug: Log what we have in context
        logger.debug(f"get_session_credentials: context type = {type(context)}")
        logger.debug(f"get_session_credentials: hasattr request_context = {hasattr(context, 'request_context')}")
        
        # Get session ID from request headers
        if hasattr(context, 'request_context') and context.request_context:
            logger.debug(f"get_session_credentials: request_context type = {type(context.request_context)}")
            if hasattr(context.request_context, 'request') and context.request_context.request:
                request = context.request_context.request
                session_id = request.headers.get("mcp-session-id")
                logger.debug(f"get_session_credentials: session_id = {session_id[:8] if session_id else 'None'}...")
                if session_id:
                    stored = session_credential_store.get(session_id)
                    if stored:
                        logger.info(f"✅ Found session credentials for {session_id[:8]}...")
                        return stored["key"], stored["creds"]
                    else:
                        logger.warning(f"⚠️  No credentials found for session {session_id[:8]}...")
            else:
                logger.warning("⚠️  request_context has no request attribute")
        else:
            logger.warning("⚠️  context has no request_context")
    except Exception as e:
        logger.error(f"Error getting session credentials: {e}")
        import traceback
        logger.error(traceback.format_exc())
    return None


# ============================================================================
# API Endpoint Tool Implementations
# ============================================================================

def create_authenticated_clob_client(operator_private_key: str, creds: Optional[ApiCreds] = None) -> ClobClient:
    """
    Create an authenticated ClobClient from a private key.
    
    Following Polymarket docs: https://docs.polymarket.com/quickstart/first-order
    
    Uses signature_type=0 (EOA) with funder set to the wallet address.
    
    Args:
        operator_private_key: The private key for signing
        creds: Optional pre-derived API credentials. If None, will create/derive them.
    
    Returns:
        Fully initialized ClobClient ready for trading
    """
    from eth_account import Account
    
    # Get funder address from private key
    account = Account.from_key(operator_private_key)
    funder_address = account.address
    
    if creds is None:
        # Create client for deriving credentials
        temp_client = ClobClient(
            host="https://clob.polymarket.com",
            chain_id=137,
            key=operator_private_key,
            signature_type=0,  # EOA signature (Type 0 per Polymarket docs)
            funder=funder_address
        )
        
        # Use create_or_derive as recommended by Polymarket docs
        creds = temp_client.create_or_derive_api_creds()
    
    # Create the full client with credentials
    client = ClobClient(
        host="https://clob.polymarket.com",
        chain_id=137,
        key=operator_private_key,
        creds=creds,
        signature_type=0,  # EOA signature (Type 0)
        funder=funder_address
    )
    
    return client


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[CREDENTIAL HELPER] Derive Polymarket API credenti"

)
async def derive_polymarket_credentials(
    context: Context,
    operator_private_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    [CREDENTIAL HELPER] Derive Polymarket API credentials from an operator private key.

    This function uses the py-clob-client to derive API credentials from the agent's
    Ethereum private key. The private key is NOT stored - only used in-memory to 
    derive credentials which are returned to the agent.

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        operator_private_key: Agent's Ethereum/Polygon private key (0x prefixed hex string).

    Returns:
        Dictionary with api_key, api_secret, api_passphrase for trading endpoints

    Example Usage:
        await derive_polymarket_credentials(operator_private_key="0x...")
    """
    # Payment already verified by @require_payment_for_tool decorator
    
    if not operator_private_key:
        return {
            "error": "Missing operator_private_key",
            "message": "You must provide your Ethereum private key to derive Polymarket credentials"
        }

    try:
        from eth_account import Account
        
        # Get funder address from private key
        account = Account.from_key(operator_private_key)
        funder_address = account.address
        
        # Initialize CLOB client following Polymarket docs:
        # https://docs.polymarket.com/quickstart/first-order
        # signature_type=0 for EOA wallets, funder = wallet address
        client = ClobClient(
            host="https://clob.polymarket.com",
            chain_id=137,
            key=operator_private_key,
            signature_type=0,  # EOA signature type (Type 0)
            funder=funder_address
        )
        
        # Use create_or_derive_api_creds as recommended by Polymarket docs
        # This creates a new key if none exists, or derives existing one
        api_creds = client.create_or_derive_api_creds()
        
        logger.info(f"Successfully derived Polymarket credentials for {funder_address[:10]}...")
        
        return {
            "success": True,
            "api_key": api_creds.api_key,
            "api_secret": api_creds.api_secret,
            "api_passphrase": api_creds.api_passphrase,
            "wallet_address": funder_address,
            "note": "Store these credentials securely. Use them for all trading endpoints."
        }

    except Exception as e:
        logger.error(f"Error in derive_polymarket_credentials: {e}")
        return {"error": str(e), "message": "Failed to derive Polymarket credentials. Ensure your private key is valid."}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="List all available prediction markets on Polymarke"

)
async def list_markets(
    context: Context,
    limit: int = 100,
    offset: int = 0,
    order: str = "volume24hr",
    ascending: bool = False,
    active: bool = True,
    closed: bool = False,
    tag: Optional[str] = None,
    slug: Optional[str] = None
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    List all available prediction markets on Polymarket with filtering and pagination options. Returns market details including question, outcomes, liquidity, and trading data.

    Generated from OpenAPI endpoint: GET /markets

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        limit: Maximum number of markets to return (default 100, max 500) (optional, default: 100)
        offset: Offset for pagination (optional, default: 0)
        order: Sort order for results (optional, default: "volume24hr")
        ascending: Whether to sort in ascending order (optional, default: False)
        active: Filter for only active (tradeable) markets (optional, default: True)
        closed: Filter for only closed markets (optional, default: False)
        tag: Filter markets by tag/category (e.g., 'politics', 'crypto', 'sports') (optional)
        slug: Filter by market slug/identifier (optional)

    Returns:
        Dictionary with API response

    Example Usage:
        # Minimal (required params only):
        await list_markets()

        # With optional parameters:
        await list_markets(
        limit=100,
        offset=0,
        order="volume24hr"
    )

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/markets"
        params = {
            "limit": limit,
            "offset": offset,
            "order": order,
            "ascending": str(ascending).lower(),
            "active": str(active).lower(),
            "closed": str(closed).lower(),
            "tag": tag,
            "slug": slug
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in list_markets: {e}")
        return {"error": str(e), "endpoint": "/markets"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get detailed information about a specific predicti"

)
async def get_market(
    context: Context,
    condition_id: Optional[str] = None,
    market_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get detailed information about a specific prediction market including current prices, outcomes, liquidity, volume, and resolution details.

    Supports two lookup methods:
    - condition_id: Use the CLOB API (hex string starting with '0x', e.g., '0x1234...')
    - market_id: Use the Gamma API (numeric ID, e.g., '12345')

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        condition_id: The unique condition ID of the market (e.g., '0x...' hex string). Used with CLOB API. Examples: "0x1234567890abcdef1234567890abcdef12345678"
        market_id: The numeric market ID (e.g., '12345'). Used with Gamma API. Examples: "521234"

    Returns:
        Dictionary with API response

    Example Usage:
        # Using condition_id (CLOB API):
        await get_market(condition_id="0x1234567890abcdef1234567890abcdef12345678")

        # Using market_id (Gamma API):
        await get_market(market_id="521234")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        # Determine which API to use based on provided parameters
        if condition_id:
            # Use CLOB API for condition_id lookups (hex strings starting with 0x)
            url = f"https://clob.polymarket.com/markets/{condition_id}"
        elif market_id:
            # Use Gamma API for numeric market_id lookups
            url = f"https://gamma-api.polymarket.com/markets/{market_id}"
        else:
            return {"error": "Either condition_id or market_id must be provided", "endpoint": "/markets/{id}"}

        params = {}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_market: {e}")
        return {"error": str(e), "endpoint": "/markets/{condition_id|market_id}"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="List all events on Polymarket. Events group relate"

)
async def list_events(
    context: Context,
    limit: int = 100,
    offset: int = 0,
    order: str = "volume",
    ascending: bool = False,
    active: bool = True,
    closed: bool = False,
    tag: Optional[str] = None,
    tag_id: Optional[int] = None,
    series_id: Optional[int] = None
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    List all events on Polymarket. Events group related prediction markets together (e.g., 'US 2024 Presidential Election' event contains multiple markets).

    Generated from OpenAPI endpoint: GET /events

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        limit: Maximum number of events to return (optional, default: 100)
        offset: Offset for pagination (optional, default: 0)
        order: Sort order - 'volume', 'startTime', 'endDate' (optional, default: "volume")
        ascending: Sort in ascending order (optional, default: False)
        active: Filter for active events only (optional, default: True)
        closed: Filter for closed events only (optional, default: False)
        tag: Filter by category tag name (optional)
        tag_id: Filter by numeric tag ID (e.g., 100639 for game bets). Use get_tags to find tag IDs (optional)
        series_id: Filter by sports league/series ID. Use list_sports to find series IDs (optional)

    Returns:
        List of events matching the filters

    Example Usage:
        # Get all active events:
        await list_events(active=True, closed=False)

        # Get NBA games using series_id from list_sports():
        await list_events(series_id=10345, active=True, closed=False)

        # Filter to just game bets (not futures) using tag_id:
        await list_events(series_id=10345, tag_id=100639, active=True, closed=False, order="startTime", ascending=True)

        # Get crypto events by tag name:
        await list_events(tag="crypto", active=True)

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/events"
        params = {
            "limit": limit,
            "offset": offset,
            "order": order,
            "ascending": str(ascending).lower(),
            "active": str(active).lower(),
            "closed": str(closed).lower(),
            "tag": tag,
            "tag_id": tag_id,
            "series_id": series_id
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in list_events: {e}")
        return {"error": str(e), "endpoint": "/events"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get detailed information about a specific event in"

)
async def get_event(
    context: Context,
    event_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get detailed information about a specific event including all associated prediction markets.

    Generated from OpenAPI endpoint: GET /events/{event_id}

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        event_id: The unique ID of the event (optional) Examples: "12345"

    Returns:
        Dictionary with API response

    Example Usage:
        await get_event(event_id="12345")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/events/{event_id}"
        params = {}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_event: {e}")
        return {"error": str(e), "endpoint": "/events/{event_id}"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get current prices and implied probabilities for p"

)
async def get_prices(
    context: Context,
    token_id: str
) -> Dict[str, Any]:
    """
    Get current price for a specific token (YES or NO outcome).

    Prices are between 0-1 representing probability (0.65 = 65% probability).
    Returns midpoint price (average of best bid and ask) plus the spread.

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get price for.
                  Get from market data: tokens[0].token_id for YES, tokens[1].token_id for NO

    Returns:
        Dictionary with price info (midpoint, spread, bid, ask)

    Example Usage:
        await get_prices(token_id="12345...")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    try:
        # Get midpoint (average of best bid/ask)
        mid_url = f"https://clob.polymarket.com/midpoint"
        mid_response = requests.get(
            mid_url,
            params={"token_id": token_id},
            headers={},
            timeout=30
        )
        mid_data = mid_response.json() if mid_response.status_code == 200 else {"mid": None}
        
        # Get spread (difference between best bid/ask)
        spread_url = f"https://clob.polymarket.com/spread"
        spread_response = requests.get(
            spread_url,
            params={"token_id": token_id},
            headers={},
            timeout=30
        )
        spread_data = spread_response.json() if spread_response.status_code == 200 else {"spread": None}
        
        # Calculate bid/ask from midpoint and spread
        mid_value = mid_data.get("mid")
        spread_value = spread_data.get("spread")
        
        midpoint: Optional[float] = float(mid_value) if mid_value is not None else None
        spread_val: Optional[float] = float(spread_value) if spread_value is not None else None
        
        bid: Optional[float] = None
        ask: Optional[float] = None
        if midpoint is not None and spread_val is not None:
            bid = round(midpoint - spread_val/2, 4)
            ask = round(midpoint + spread_val/2, 4)
        
        return {
            "token_id": token_id,
            "midpoint": midpoint,
            "spread": spread_val,
            "estimated_bid": bid,
            "estimated_ask": ask,
            "price_formatted": f"{midpoint:.2%}" if midpoint else "N/A",
            "message": "Use midpoint as the current price estimate"
        }

    except Exception as e:
        logger.error(f"Error in get_prices: {e}")
        return {"error": str(e), "endpoint": "/prices"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get historical price data for a prediction market "

)
async def get_price_history(
    context: Context,
    market_id: Optional[str] = None,
    startTs: Optional[int] = None,
    endTs: Optional[int] = None,
    interval: str = "1h",
    fidelity: int = 100
) -> Dict[str, Any]:
    """
    Get historical price data for a prediction market outcome. Useful for charting and analyzing market movements over time.

    Generated from OpenAPI endpoint: GET /prices/history

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        market_id: The market condition ID to get price history for (optional)
        startTs: Start timestamp (Unix seconds) (optional)
        endTs: End timestamp (Unix seconds) (optional)
        interval: Time interval for data points (optional, default: "1h")
        fidelity: Number of data points to return (optional, default: 100)

    Returns:
        Dictionary with API response

    Example Usage:
        # Minimal (required params only):
        await get_price_history(market_id="example")

        # With optional parameters:
        await get_price_history(
        market_id="example",
        interval="1h",
        fidelity=100
    )

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/prices/history"
        params = {
            "market_id": market_id,
            "startTs": startTs,
            "endTs": endTs,
            "interval": interval,
            "fidelity": fidelity
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_price_history: {e}")
        return {"error": str(e), "endpoint": "/prices/history"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get the order book for a specific market token sho"

)
async def get_orderbook(
    context: Context,
    token_id: str
) -> Dict[str, Any]:
    """
    Get the order book for a specific market token showing bid and ask orders with prices and sizes.

    Uses the CLOB API which requires a token_id (outcome token address).

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get the order book for (YES or NO outcome token).
                  Get this from market data: tokens[0].token_id for YES, tokens[1].token_id for NO

    Returns:
        Dictionary with bids and asks arrays

    Example Usage:
        await get_orderbook(token_id="12345...")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    try:
        # Use CLOB API for orderbook (not Gamma API)
        url = f"https://clob.polymarket.com/book"
        params = {
            "token_id": token_id
        }
        headers = {}

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_orderbook: {e}")
        return {"error": str(e), "endpoint": "/book"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get the midpoint price for a market token (average"

)
async def get_midpoint(
    context: Context,
    token_id: str
) -> Dict[str, Any]:
    """
    Get the midpoint price for a market token (average between best bid and ask).

    Uses the CLOB API which requires a token_id.

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get midpoint price for.
                  Get this from market data: tokens[0].token_id for YES, tokens[1].token_id for NO

    Returns:
        Dictionary with midpoint price

    Example Usage:
        await get_midpoint(token_id="12345...")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    try:
        # Use CLOB API for midpoint (not Gamma API)
        url = f"https://clob.polymarket.com/midpoint"
        params = {
            "token_id": token_id
        }
        headers = {}

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_midpoint: {e}")
        return {"error": str(e), "endpoint": "/midpoint"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get the bid-ask spread for a market token showing "

)
async def get_spread(
    context: Context,
    token_id: str
) -> Dict[str, Any]:
    """
    Get the bid-ask spread for a market token showing the difference between best bid and best ask prices.

    Uses the CLOB API which requires a token_id.

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get spread for.
                  Get this from market data: tokens[0].token_id for YES, tokens[1].token_id for NO

    Returns:
        Dictionary with spread info

    Example Usage:
        await get_spread(token_id="12345...")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    try:
        # Use CLOB API for spread (not Gamma API)
        url = f"https://clob.polymarket.com/spread"
        params = {
            "token_id": token_id
        }
        headers = {}

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_spread: {e}")
        return {"error": str(e), "endpoint": "/spread"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get recent trade history for a market showing exec"

)
async def get_trades(
    context: Context,
    token_id: Optional[str] = None,
    limit: int = 100
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Get your trade history showing executed transactions with prices, sizes, and timestamps.
    
    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.
    
    This endpoint returns YOUR trades (authenticated user's trade history).

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: Filter trades by token ID (optional)
        limit: Maximum number of trades to return (optional, default: 100)

    Returns:
        List of trade objects

    Example Usage:
        # Get all your recent trades:
        await get_trades(limit=10)

        # Get your trades for a specific token:
        await get_trades(token_id="12345...", limit=100)

        Note: 'context' parameter is auto-injected by MCP framework
    """
    try:
        # Get session credentials (required for CLOB trades endpoint)
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Use py-clob-client to get trades
        from py_clob_client.clob_types import TradeParams
        
        params = TradeParams()
        if token_id:
            params = TradeParams(asset_id=token_id)
        
        trades = client.get_trades(params)
        
        # Limit results if needed
        if isinstance(trades, list) and len(trades) > limit:
            trades = trades[:limit]
        
        return {
            "success": True,
            "trades": trades,
            "count": len(trades) if isinstance(trades, list) else 0,
            "message": "Your trade history retrieved successfully"
        }

    except Exception as e:
        logger.error(f"Error in get_trades: {e}")
        return {"error": str(e), "endpoint": "/trades"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get time series data for market metrics including "

)
async def get_timeseries(
    context: Context,
    market_id: Optional[str] = None,
    startTs: Optional[int] = None,
    endTs: Optional[int] = None,
    interval: str = "1h"
) -> Dict[str, Any]:
    """
    Get time series data for market metrics including price, volume, and liquidity over time periods.

    Generated from OpenAPI endpoint: GET /timeseries

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        market_id: The market condition ID (optional)
        startTs: Start timestamp (Unix seconds) (optional)
        endTs: End timestamp (Unix seconds) (optional)
        interval: Time interval (optional, default: "1h")

    Returns:
        Dictionary with API response

    Example Usage:
        # Minimal (required params only):
        await get_timeseries(market_id="example")

        # With optional parameters:
        await get_timeseries(market_id="example", interval="1h")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/timeseries"
        params = {
            "market_id": market_id,
            "startTs": startTs,
            "endTs": endTs,
            "interval": interval
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_timeseries: {e}")
        return {"error": str(e), "endpoint": "/timeseries"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="1000000000000000",  # 0.001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING - REQUIRES AGENT CREDENTIALS] Create a ne"

)
async def create_order(
    context: Context,
    token_id: str,
    side: str,
    price: float,
    size: float,
    order_type: str = "GTC",
    expiration: Optional[int] = None
) -> Dict[str, Any]:
    """
    [TRADING] Create a new order to buy or sell prediction market shares.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        token_id: The token ID to trade (outcome token address)
        side: Order side - "BUY" or "SELL"
        price: Limit price for the order (0-1 range for probability)
        size: Size of the order in USDC
        order_type: Order type - "GTC" (Good Till Cancelled), "FOK" (Fill or Kill), "GTD" (Good Till Date)
        expiration: Expiration timestamp for GTD orders (Unix seconds)

    Returns:
        Dictionary with order details or error

    Example Usage:
        await create_order(token_id="0x...", side="BUY", price=0.65, size=10.0)
    """
    try:
        # Get session credentials (required)
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        
        # Get funder address from private key (EOA wallet address)
        from eth_account import Account
        account = Account.from_key(private_key)
        funder_address = account.address
        
        # Create client with correct signature type and funder per Polymarket docs:
        # https://docs.polymarket.com/quickstart/first-order
        # Type 0 = EOA wallet, funder = your wallet address
        client = ClobClient(
            host="https://clob.polymarket.com",
            chain_id=137,
            key=private_key,
            creds=creds,
            signature_type=0,  # EOA signature type
            funder=funder_address  # Required for order signing
        )
        
        # Build and submit order using OrderArgs
        from py_clob_client.clob_types import OrderArgs
        from py_clob_client.order_builder.constants import BUY, SELL
        order_side = BUY if side.upper() == "BUY" else SELL
        
        # Create OrderArgs object
        order_args = OrderArgs(
            token_id=token_id,
            price=float(price),
            size=float(size),
            side=order_side
        )
        
        # Create the order
        order = client.create_order(order_args)
        
        # Post the order
        result = client.post_order(order)
        
        logger.info(f"Order created successfully: {result}")
        return {
            "success": True,
            "order": result,
            "message": "Order submitted successfully"
        }

    except Exception as e:
        logger.error(f"Error in create_order: {e}")
        return {"error": str(e), "endpoint": "/order"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="1000000000000000",  # 0.001 tokens (market orders are more expensive)
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Create a market order for immediate execution"

)
async def create_market_order(
    context: Context,
    token_id: str,
    side: str,
    amount: float,
    worst_price: Optional[float] = None
) -> Dict[str, Any]:
    """
    [TRADING] Create a market order for immediate execution at best available price.

    Unlike limit orders, market orders execute immediately at the current market price.
    Use this when you want guaranteed execution rather than a specific price.
    
    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        token_id: The token ID to trade (outcome token address, get from market data)
        side: Order side - "BUY" or "SELL"
        amount: Amount in USDC to spend (for BUY) or shares to sell (for SELL)
        worst_price: Optional worst acceptable price (0-1). If market moves beyond this, order fails.
                     For BUY: max price you're willing to pay. For SELL: min price you'll accept.

    Returns:
        Dictionary with order execution details

    Example Usage:
        # Buy $10 worth at market price:
        await create_market_order(token_id="0x...", side="BUY", amount=10.0)
        
        # Buy $10 worth but only if price is below 0.65:
        await create_market_order(token_id="0x...", side="BUY", amount=10.0, worst_price=0.65)
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        
        # Get funder address from private key
        from eth_account import Account
        account = Account.from_key(private_key)
        funder_address = account.address
        
        client = ClobClient(
            host="https://clob.polymarket.com",
            chain_id=137,
            key=private_key,
            creds=creds,
            signature_type=0,  # EOA signature type
            funder=funder_address
        )
        
        # Build market order args
        from py_clob_client.clob_types import MarketOrderArgs
        from py_clob_client.order_builder.constants import BUY, SELL
        
        order_side = BUY if side.upper() == "BUY" else SELL
        
        # Create market order args
        # price=0 means execute at best available market price (no limit)
        market_order_args = MarketOrderArgs(
            token_id=token_id,
            amount=float(amount),
            side=order_side,
            price=float(worst_price) if worst_price is not None else 0.0
        )
        
        # Create and submit the market order
        order = client.create_market_order(market_order_args)
        
        logger.info(f"Market order created successfully: {order}")
        return {
            "success": True,
            "order": order,
            "message": "Market order submitted successfully. Check 'order' for execution details."
        }

    except Exception as e:
        logger.error(f"Error in create_market_order: {e}")
        return {"error": str(e), "message": "Failed to create market order"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="500000000000000",  # 0.0005 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING - REQUIRES AGENT CREDENTIALS] Cancel an o"

)
async def cancel_order(
    context: Context,
    order_id: str
) -> Dict[str, Any]:
    """
    [TRADING] Cancel an open order by its order ID.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        order_id: The unique order ID to cancel

    Returns:
        Dictionary with cancellation result
    """
    try:
        # Get session credentials (required)
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Cancel the order
        result = client.cancel(order_id)
        
        logger.info(f"Order {order_id} cancelled successfully")
        return {
            "success": True,
            "order_id": order_id,
            "result": result,
            "message": "Order cancelled successfully"
        }

    except Exception as e:
        logger.error(f"Error in cancel_order: {e}")
        return {"error": str(e), "message": "Failed to cancel order"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING - REQUIRES AGENT CREDENTIALS] Get all ord"

)
async def get_orders(
    context: Context,
    market: Optional[str] = None,
    asset_id: Optional[str] = None,
    state: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Get all orders for the agent's account.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        market: Filter by market condition ID (optional)
        asset_id: Filter by asset/token ID (optional)
        state: Filter by order state - "open", "matched", "cancelled" (optional)

    Returns:
        List of orders
    """
    try:
        # Get session credentials (required)
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Get orders with optional filters
        from py_clob_client.clob_types import OpenOrderParams
        if asset_id:
            params = OpenOrderParams(asset_id=asset_id)
            orders = client.get_orders(params)
        else:
            orders = client.get_orders()
        
        return {
            "success": True,
            "orders": orders,
            "count": len(orders) if isinstance(orders, list) else 0
        }

    except Exception as e:
        logger.error(f"Error in get_orders: {e}")
        return {"error": str(e), "message": "Failed to get orders"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="1000000000000000",  # 0.001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING - REQUIRES AGENT CREDENTIALS] Cancel all "

)
async def cancel_all_orders(
    context: Context,
    market: Optional[str] = None,
    asset_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Cancel all open orders for the agent's account.
    
    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        market: Optional market condition ID to cancel orders for
        asset_id: Optional asset/token ID to cancel orders for

    Returns:
        Dictionary with cancellation result
    """
    try:
        # Get session credentials (required)
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Cancel all orders
        result = client.cancel_all()
        
        logger.info(f"All orders cancelled successfully")
        return {
            "success": True,
            "result": result,
            "message": "All orders cancelled"
        }

    except Exception as e:
        logger.error(f"Error in cancel_all_orders: {e}")
        return {"error": str(e), "message": "Failed to cancel orders"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Get account balances - cash (USDC) and portfolio value"

)
async def get_balance(
    context: Context
) -> Dict[str, Any]:
    """
    [TRADING] Get account balances - both cash and portfolio value (like Polymarket UI).
    
    This returns both values you see on Polymarket UI:
    - Cash Balance: USDC available for trading
    - Portfolio Balance: Total value of all open positions
    - Total Balance: Cash + Portfolio combined
    
    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)

    Returns:
        Dictionary with cash_balance, portfolio_balance, total_balance, and positions list
    """
    try:
        # Get session credentials (required)
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # 1. Get COLLATERAL (USDC cash) balance - "Cash Balance" in Polymarket UI
        cash_params = BalanceAllowanceParams(asset_type=AssetType.COLLATERAL, signature_type=0)  # type: ignore
        cash_balance = client.get_balance_allowance(cash_params)
        
        # Parse cash balance
        if isinstance(cash_balance, dict):
            usdc_raw = cash_balance.get("balance", "0")
        else:
            usdc_raw = "0"
        
        cash_amount = float(usdc_raw) / 1e6 if usdc_raw else 0.0  # USDC has 6 decimals
        
        # 2. Get all positions to calculate portfolio value
        from py_clob_client.clob_types import TradeParams
        trades_response = client.get_trades(TradeParams())
        
        # Parse positions and calculate portfolio value
        positions = []
        portfolio_value = 0.0
        
        if isinstance(trades_response, list):
            # Group trades by asset_id to calculate net position for each
            position_map: Dict[str, Dict[str, Any]] = {}
            
            for trade in trades_response:
                if isinstance(trade, dict):
                    asset_id = trade.get("asset_id", "")
                    side = trade.get("side", "").upper()
                    size = float(trade.get("size", 0))
                    price = float(trade.get("price", 0))
                    
                    if asset_id not in position_map:
                        position_map[asset_id] = {
                            "asset_id": asset_id,
                            "market": trade.get("market", ""),
                            "outcome": trade.get("outcome", ""),
                            "shares": 0.0,
                            "avg_price": 0.0,
                            "total_cost": 0.0,
                            "trade_count": 0
                        }
                    
                    pos = position_map[asset_id]
                    if side == "BUY":
                        pos["shares"] += size
                        pos["total_cost"] += size * price
                    else:  # SELL
                        pos["shares"] -= size
                        pos["total_cost"] -= size * price
                    pos["trade_count"] += 1
            
            # Calculate current value for each position
            for asset_id, pos in position_map.items():
                if pos["shares"] > 0.01:  # Only include non-zero positions
                    # Get current price for this token
                    try:
                        current_price = client.get_last_trade_price(asset_id)
                        if isinstance(current_price, dict):
                            last_price = float(current_price.get("price", 0.5))
                        else:
                            last_price = 0.5  # Default to 50% if unknown
                    except Exception:
                        last_price = 0.5
                    
                    current_value = pos["shares"] * last_price
                    avg_price = pos["total_cost"] / pos["shares"] if pos["shares"] > 0 else 0
                    
                    positions.append({
                        "asset_id": asset_id,
                        "market": pos["market"],
                        "outcome": pos["outcome"],
                        "shares": round(pos["shares"], 4),
                        "avg_entry_price": round(avg_price, 4),
                        "current_price": round(last_price, 4),
                        "current_value": round(current_value, 2),
                        "pnl": round(current_value - pos["total_cost"], 2),
                        "pnl_percent": round(((current_value / pos["total_cost"]) - 1) * 100, 2) if pos["total_cost"] > 0 else 0
                    })
                    portfolio_value += current_value
        
        total_balance = cash_amount + portfolio_value
        
        return {
            "success": True,
            "cash_balance": {
                "amount": round(cash_amount, 2),
                "formatted": f"${cash_amount:.2f}"
            },
            "portfolio_balance": {
                "amount": round(portfolio_value, 2),
                "formatted": f"${portfolio_value:.2f}",
                "position_count": len(positions)
            },
            "total_balance": {
                "amount": round(total_balance, 2),
                "formatted": f"${total_balance:.2f}"
            },
            "positions": positions,
            "message": f"Cash: ${cash_amount:.2f} | Portfolio: ${portfolio_value:.2f} | Total: ${total_balance:.2f}"
        }

    except Exception as e:
        logger.error(f"Error in get_balance: {e}")
        return {"error": str(e), "message": "Failed to get balance"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING - REQUIRES AGENT CREDENTIALS] Get all ope"

)
async def get_positions(
    context: Context,
    market: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Get all open positions for the agent's account.
    
    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        market: Optional market condition ID to filter positions

    Returns:
        Dictionary with positions information
    """
    try:
        # Get session credentials (required)
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Get trades which show positions
        trades = client.get_trades()
        
        return {
            "success": True,
            "trades": trades,
            "message": "Trades/positions retrieved successfully"
        }

    except Exception as e:
        logger.error(f"Error in get_positions: {e}")
        return {"error": str(e), "message": "Failed to get positions"}


# ============================================================================
# ADDITIONAL AUTHENTICATED ENDPOINTS
# ============================================================================


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Get a specific order by its order hash/ID"

)
async def get_order(
    context: Context,
    order_id: str
) -> Dict[str, Any]:
    """
    [TRADING] Get details of a specific order by its order hash/ID.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        order_id: The unique order hash/ID to fetch

    Returns:
        Dictionary with order details
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        order = client.get_order(order_id)
        
        return {
            "success": True,
            "order": order,
            "message": "Order retrieved successfully"
        }

    except Exception as e:
        logger.error(f"Error in get_order: {e}")
        return {"error": str(e), "message": "Failed to get order"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="500000000000000",  # 0.0005 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Cancel multiple orders by their order IDs"

)
async def cancel_orders(
    context: Context,
    order_ids: str
) -> Dict[str, Any]:
    """
    [TRADING] Cancel multiple orders by their order IDs.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        order_ids: Comma-separated list of order IDs to cancel (e.g., "id1,id2,id3")

    Returns:
        Dictionary with cancellation results
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Parse comma-separated order IDs
        ids = [id.strip() for id in order_ids.split(",") if id.strip()]
        
        result = client.cancel_orders(ids)
        
        return {
            "success": True,
            "result": result,
            "cancelled_count": len(ids),
            "message": f"Cancelled {len(ids)} orders"
        }

    except Exception as e:
        logger.error(f"Error in cancel_orders: {e}")
        return {"error": str(e), "message": "Failed to cancel orders"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="500000000000000",  # 0.0005 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Cancel all orders for a specific market"

)
async def cancel_market_orders(
    context: Context,
    market: Optional[str] = None,
    asset_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Cancel all orders for a specific market or asset.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        market: Market condition ID to cancel orders for (optional)
        asset_id: Token/asset ID to cancel orders for (optional)

    Returns:
        Dictionary with cancellation result
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Pass only non-None values to cancel_market_orders
        kwargs = {}
        if market is not None:
            kwargs["market"] = market
        if asset_id is not None:
            kwargs["asset_id"] = asset_id
        result = client.cancel_market_orders(**kwargs) if kwargs else client.cancel_all()
        
        return {
            "success": True,
            "result": result,
            "message": "Market orders cancelled successfully"
        }

    except Exception as e:
        logger.error(f"Error in cancel_market_orders: {e}")
        return {"error": str(e), "message": "Failed to cancel market orders"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Update USDC trading allowance for the exchange"

)
async def update_balance_allowance(
    context: Context,
    allowance_amount: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Update USDC allowance for trading on Polymarket.

    This sets how much USDC the exchange contract can spend on your behalf.
    Required before placing orders if allowance is insufficient.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        allowance_amount: Amount to approve (optional, defaults to max uint256)

    Returns:
        Dictionary with transaction result
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        result = client.update_balance_allowance()
        
        return {
            "success": True,
            "result": result,
            "message": "Balance allowance updated successfully"
        }

    except Exception as e:
        logger.error(f"Error in update_balance_allowance: {e}")
        return {"error": str(e), "message": "Failed to update balance allowance"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="50000000000000",  # 0.00005 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Get user notifications from Polymarket"

)
async def get_notifications(
    context: Context
) -> Dict[str, Any]:
    """
    [TRADING] Get notifications for the authenticated user.

    Returns order fills, settlements, and other account notifications.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)

    Returns:
        Dictionary with notifications list
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        notifications = client.get_notifications()
        
        return {
            "success": True,
            "notifications": notifications,
            "count": len(notifications) if isinstance(notifications, list) else 0,
            "message": "Notifications retrieved successfully"
        }

    except Exception as e:
        logger.error(f"Error in get_notifications: {e}")
        return {"error": str(e), "message": "Failed to get notifications"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="50000000000000",  # 0.00005 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Clear/dismiss all notifications"

)
async def drop_notifications(
    context: Context
) -> Dict[str, Any]:
    """
    [TRADING] Clear/dismiss all notifications for the authenticated user.

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)

    Returns:
        Dictionary with result
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        result = client.drop_notifications()
        
        return {
            "success": True,
            "result": result,
            "message": "Notifications cleared successfully"
        }

    except Exception as e:
        logger.error(f"Error in drop_notifications: {e}")
        return {"error": str(e), "message": "Failed to clear notifications"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="2000000000000000",  # 0.002 tokens (higher for batch operations)
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="[TRADING] Submit multiple orders at once (batch)"

)
async def post_orders(
    context: Context,
    orders_json: str
) -> Dict[str, Any]:
    """
    [TRADING] Submit multiple orders at once (batch operation).

    REQUIRES SESSION AUTH: Initialize session with X-Polymarket-Key header first.

    Args:
        context: MCP context (auto-injected by framework)
        orders_json: JSON array of order objects. Each order needs:
            - token_id: Token ID to trade
            - side: "BUY" or "SELL"
            - price: Limit price (0-1)
            - size: Size in USDC

    Returns:
        Dictionary with batch order results

    Example:
        orders_json = '[{"token_id":"0x...","side":"BUY","price":0.5,"size":10}]'
    """
    try:
        session_creds = get_session_credentials(context)
        
        if not session_creds:
            return {
                "error": "No Polymarket credentials available",
                "message": "Initialize session with X-Polymarket-Key header containing your Polymarket private key"
            }
        
        private_key, creds = session_creds
        client = create_authenticated_clob_client(private_key, creds)
        
        # Parse orders JSON
        orders_data = json.loads(orders_json)
        if not isinstance(orders_data, list):
            return {"error": "orders_json must be a JSON array", "message": "Invalid input format"}
        
        from py_clob_client.clob_types import OrderArgs
        from py_clob_client.order_builder.constants import BUY, SELL
        
        # Build signed orders
        signed_orders = []
        for order_data in orders_data:
            order_side = BUY if order_data.get("side", "").upper() == "BUY" else SELL
            order_args = OrderArgs(
                token_id=order_data["token_id"],
                price=float(order_data["price"]),
                size=float(order_data["size"]),
                side=order_side
            )
            signed_order = client.create_order(order_args)
            signed_orders.append(signed_order)
        
        # Post all orders
        result = client.post_orders(signed_orders)
        
        return {
            "success": True,
            "result": result,
            "orders_submitted": len(signed_orders),
            "message": f"Submitted {len(signed_orders)} orders"
        }

    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}", "message": "Failed to parse orders_json"}
    except Exception as e:
        logger.error(f"Error in post_orders: {e}")
        return {"error": str(e), "message": "Failed to post orders"}


# ============================================================================
# PUBLIC ENDPOINTS (No authentication required)
# ============================================================================


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Search for markets by keyword. Useful for finding "

)
async def search_markets(
    context: Context,
    query: Optional[str] = None,
    limit: int = 20
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Search for markets by keyword. Useful for finding specific prediction markets by topic, name, or related terms.

    Generated from OpenAPI endpoint: GET /search

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        query: Search query string (optional) Examples: "Trump", "Bitcoin price", "Super Bowl winner"
        limit: Maximum number of results (optional, default: 20)

    Returns:
        Dictionary with API response

    Example Usage:
        # Minimal (required params only):
        await search_markets(query="Trump")

        # With optional parameters:
        await search_markets(query="Trump", limit=20)

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/search"
        params = {
            "query": query,
            "limit": limit
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in search_markets: {e}")
        return {"error": str(e), "endpoint": "/search"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="50000000000000",  # 5e-05 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get list of all available market tags/categories f"

)
async def get_tags(
    context: Context
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Get list of all available market tags/categories for filtering markets (e.g., 'politics', 'crypto', 'sports', 'entertainment').

    Generated from OpenAPI endpoint: GET /tags

    Args:
        context: MCP context (auto-injected by framework, not user-provided)


    Returns:
        List of available tags with their IDs, labels, and slugs

    Example Usage:
        # Get all tags
        await get_tags()

        # Then use tag_id to filter events:
        # await list_events(tag_id=100639)  # 100639 = game bets
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/tags"
        params = {}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_tags: {e}")
        return {"error": str(e), "endpoint": "/tags"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="50000000000000",  # 5e-05 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get list of all supported sports leagues with their series IDs"

)
async def list_sports(
    context: Context
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Get list of all supported sports leagues on Polymarket with their series IDs.

    Use this to discover sports leagues, then use the series_id with list_events()
    to filter events for a specific league.

    Generated from OpenAPI endpoint: GET /sports

    Args:
        context: MCP context (auto-injected by framework, not user-provided)

    Returns:
        List of sports leagues with:
        - id: Internal sport ID
        - sport: Sport code (e.g., 'nba', 'nfl', 'epl')
        - series: Series ID to use with list_events(series_id=X)
        - tags: Comma-separated tag IDs associated with this sport
        - image: League logo URL
        - resolution: Official result source URL

    Example Usage:
        # Get all sports leagues
        sports = await list_sports()
        
        # Find NBA series_id (e.g., 10345)
        nba = next(s for s in sports if s['sport'] == 'nba')
        
        # Then get NBA events:
        # await list_events(series_id=nba['series'], active=True, closed=False)
        
        # Filter to just game bets (not futures) using tag_id=100639:
        # await list_events(series_id=nba['series'], tag_id=100639, order='startTime', ascending=True)
    
    Note: /sports only returns automated leagues. For others (UFC, Boxing, F1, Golf, Chess),
    use tag IDs via list_events(tag_id=X).
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/sports"
        params = {}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in list_sports: {e}")
        return {"error": str(e), "endpoint": "/sports"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="50000000000000",  # 5e-05 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get all series (grouped recurring events like BTC Up/Down Hourly)"

)
async def list_series(
    context: Context,
    limit: int = 100,
    offset: int = 0,
    active: bool = True
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Get all series on Polymarket. Series are groups of recurring events (e.g., 'BTC Up or Down Hourly').
    
    Series aggregate related markets that repeat on a schedule (hourly, daily, weekly).

    Generated from OpenAPI endpoint: GET /series

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        limit: Maximum number of series to return (optional, default: 100)
        offset: Offset for pagination (optional, default: 0)
        active: Filter for active series only (optional, default: True)

    Returns:
        List of series with:
        - id: Series ID (use with list_events series_id parameter)
        - ticker: Short identifier
        - title: Display name (e.g., 'BTC Up or Down Hourly')
        - seriesType: Type of series (e.g., 'single')
        - recurrence: How often events repeat (e.g., 'hourly', 'daily')
        - events: Array of events in this series
        - volume: Total volume traded across all events
        - liquidity: Current liquidity

    Example Usage:
        # Get all active series
        series = await list_series(active=True)
        
        # Find hourly crypto series
        crypto_hourly = [s for s in series if s['recurrence'] == 'hourly']
        
        # Get events for a specific series:
        # await list_events(series_id=series['id'])
    """
    # Payment already verified by @require_payment_for_tool decorator
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/series"
        params = {
            "limit": limit,
            "offset": offset,
            "active": str(active).lower()
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in list_series: {e}")
        return {"error": str(e), "endpoint": "/series"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="50000000000000",  # 5e-05 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get comments on a specific event or market"

)
async def get_comments(
    context: Context,
    parent_entity_id: str,
    entity_type: str = "event",
    limit: int = 50,
    offset: int = 0
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Get comments on a specific event or market.

    Generated from OpenAPI endpoint: GET /comments

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        parent_entity_id: ID of the event or market to get comments for (required)
        entity_type: Type of entity - 'event' or 'market' (optional, default: 'event')
        limit: Maximum number of comments to return (optional, default: 50)
        offset: Offset for pagination (optional, default: 0)

    Returns:
        List of comments with user info, content, and timestamps

    Example Usage:
        # Get comments on an event
        comments = await get_comments(parent_entity_id="123456", entity_type="event")
    """
    # Payment already verified by @require_payment_for_tool decorator
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/comments"
        params = {
            "parent_entity_id": parent_entity_id,
            "entity_entity_type": entity_type,
            "limit": limit,
            "offset": offset
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_comments: {e}")
        return {"error": str(e), "endpoint": "/comments"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="50000000000000",  # 5e-05 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get a user profile by address"

)
async def get_profile(
    context: Context,
    address: str
) -> Dict[str, Any]:
    """
    Get a user profile by wallet address.

    Generated from OpenAPI endpoint: GET /profiles/{address}

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        address: Wallet address of the user profile to fetch (required)

    Returns:
        User profile with username, bio, stats, and activity

    Example Usage:
        profile = await get_profile(address="0x1234...")
    """
    # Payment already verified by @require_payment_for_tool decorator
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/profiles/{address}"
        params = {}
        headers = {}

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_profile: {e}")
        return {"error": str(e), "endpoint": f"/profiles/{address}"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get reward/incentive information for markets and t"

)
async def get_rewards(
    context: Context,
    market_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get reward/incentive information for markets and trading activity.

    Generated from OpenAPI endpoint: GET /rewards

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        market_id: Optional market ID to check rewards for (optional)

    Returns:
        Dictionary with API response

    Example Usage:
        await get_rewards()

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/rewards"
        params = {
            "market_id": market_id
        }
        params = {k: v for k, v in params.items() if v is not None}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_rewards: {e}")
        return {"error": str(e), "endpoint": "/rewards"}


@mcp.tool()
@require_payment_for_tool(
    price=TokenAmount(
        amount="100000000000000",  # 0.0001 tokens
        asset=TokenAsset(
            address="0x3e17730bb2ca51a8D5deD7E44c003A2e95a4d822",
            decimals=6,
            network="sepolia",
            eip712=EIP712Domain(
                name="IATPWallet",
                version="1"
            )
        )
    ),
    description="Get notification preferences for the authenticated"

)
async def get_notification_preferences(
    context: Context
) -> Dict[str, Any]:
    """
    Get notification preferences for the authenticated user.

    Generated from OpenAPI endpoint: GET /notifications/preferences

    Args:
        context: MCP context (auto-injected by framework, not user-provided)


    Returns:
        Dictionary with API response

    Example Usage:
        await get_notification_preferences()
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/notifications/preferences"
        params = {}
        headers = {}
        # No auth required for this API

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        return response.json()

    except Exception as e:
        logger.error(f"Error in get_notification_preferences: {e}")
        return {"error": str(e), "endpoint": "/notifications/preferences"}


# TODO: Add your API-specific functions here

# ============================================================================
# APPLICATION SETUP WITH STARLETTE MIDDLEWARE
# ============================================================================

def create_app_with_middleware():
    """
    Create Starlette app with d402 payment middleware.
    
    Strategy:
    1. Get FastMCP's Starlette app via streamable_http_app()
    2. Extract payment configs from @require_payment_for_tool decorators
    3. Add Starlette middleware with extracted configs
    4. Single source of truth - no duplication!
    """
    logger.info("🔧 Creating FastMCP app with middleware...")
    
    # Get FastMCP's Starlette app
    app = mcp.streamable_http_app()
    logger.info(f"✅ Got FastMCP Starlette app")
    
    # Extract payment configs from decorators (single source of truth!)
    tool_payment_configs = extract_payment_configs_from_mcp(mcp, SERVER_ADDRESS)
    logger.info(f"📊 Extracted {len(tool_payment_configs)} payment configs from @require_payment_for_tool decorators")
    
    # D402 Configuration
    facilitator_url = os.getenv("FACILITATOR_URL") or os.getenv("D402_FACILITATOR_URL")
    operator_key = os.getenv("MCP_OPERATOR_PRIVATE_KEY")
    network = os.getenv("NETWORK", "sepolia")
    testing_mode = os.getenv("D402_TESTING_MODE", "false").lower() == "true"
    
    # Log D402 configuration with prominent facilitator info
    logger.info("="*60)
    logger.info("D402 Payment Protocol Configuration:")
    logger.info(f"  Server Address: {SERVER_ADDRESS}")
    logger.info(f"  Network: {network}")
    logger.info(f"  Operator Key: {'✅ Set' if operator_key else '❌ Not set'}")
    logger.info(f"  Testing Mode: {'⚠️  ENABLED (bypasses facilitator)' if testing_mode else '✅ DISABLED (uses facilitator)'}")
    logger.info("="*60)
    
    if not facilitator_url and not testing_mode:
        logger.error("❌ FACILITATOR_URL required when testing_mode is disabled!")
        raise ValueError("Set FACILITATOR_URL or enable D402_TESTING_MODE=true")
    
    if facilitator_url:
        logger.info(f"🌐 FACILITATOR: {facilitator_url}")
        if "localhost" in facilitator_url or "127.0.0.1" in facilitator_url or "host.docker.internal" in facilitator_url:
            logger.info(f"   📍 Using LOCAL facilitator for development")
        else:
            logger.info(f"   🌍 Using REMOTE facilitator for production")
    else:
        logger.warning("⚠️  D402 Testing Mode - Facilitator bypassed")
    logger.info("="*60)
    
    # Add CORS middleware first (processes before other middleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Allow all origins
        allow_credentials=True,
        allow_methods=["*"],  # Allow all methods
        allow_headers=["*"],  # Allow all headers
        expose_headers=["mcp-session-id"],  # Expose custom headers to browser
    )
    logger.info("✅ Added CORS middleware (allow all origins, expose mcp-session-id)")
    
    # Add D402 payment middleware with extracted configs
    app.add_middleware(
        D402PaymentMiddleware,
        tool_payment_configs=tool_payment_configs,
        server_address=SERVER_ADDRESS,
        requires_auth=False,  # Only checks payment
        testing_mode=testing_mode,
        facilitator_url=facilitator_url,
        facilitator_api_key=os.getenv("D402_FACILITATOR_API_KEY"),
        server_name="polymarket-api-mcp-server"  # MCP server ID for tracking
    )
    logger.info("✅ Added D402PaymentMiddleware")
    logger.info("   - Payment-only mode")
    
    # Add Polymarket auth middleware to handle X-Polymarket-Key header
    # This derives and caches Polymarket API credentials for the session
    app.add_middleware(PolymarketAuthMiddleware)
    logger.info("✅ Added PolymarketAuthMiddleware (session-based credential caching)")
    
    # Add health check endpoint (bypasses middleware)
    @app.route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        """Health check endpoint for container orchestration.
        
        Includes geoblock check to verify Polymarket API is accessible from this region.
        """
        # Check geoblock status
        geoblock_status = await check_polymarket_geoblock()
        
        if geoblock_status.get("blocked"):
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "service": "polymarket-api-mcp-server",
                    "reason": "geoblocked",
                    "geoblock": geoblock_status,
                    "timestamp": datetime.now().isoformat()
                }
            )
        
        return JSONResponse(
            content={
                "status": "healthy",
                "service": "polymarket-api-mcp-server",
                "geoblock": geoblock_status,
                "timestamp": datetime.now().isoformat()
            }
        )
    logger.info("✅ Added /health endpoint with geoblock check")
    
    return app

if __name__ == "__main__":
    import asyncio
    
    logger.info("="*80)
    logger.info(f"Starting Polymarket API MCP Server")
    logger.info("="*80)
    logger.info("Architecture:")
    logger.info("  1. D402PaymentMiddleware intercepts requests")
    logger.info("     - Checks payment → HTTP 402 if missing")
    logger.info("  2. FastMCP processes valid requests with tool decorators")
    logger.info("="*80)
    
    # Run geoblock check on startup
    asyncio.run(startup_geoblock_check())
    
    # Create app with middleware
    app = create_app_with_middleware()
    
    # Run with uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
    )
