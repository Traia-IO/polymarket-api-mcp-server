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
from py_clob_client.clob_types import ApiCreds

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


# API Endpoint Tool Implementations

def create_authenticated_clob_client(operator_private_key: str) -> ClobClient:
    """
    Create an authenticated ClobClient from a private key.
    
    Derives API credentials and returns a fully initialized client ready for trading.
    This simplifies trading endpoints - they only need the private key.
    """
    # First create a client just for deriving credentials
    temp_client = ClobClient(
        host="https://clob.polymarket.com",
        chain_id=137,
        key=operator_private_key,
        signature_type=2  # EOA signature
    )
    
    # Derive the API credentials
    creds = temp_client.derive_api_key()
    
    # Now create the full client with both key and creds
    client = ClobClient(
        host="https://clob.polymarket.com",
        chain_id=137,
        key=operator_private_key,
        creds=creds,
        signature_type=2  # EOA signature
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
        # Initialize CLOB client with the agent's private key
        # Using Polygon mainnet (chain_id=137) for production
        # signature_type=2 for EOA wallets
        client = ClobClient(
            host="https://clob.polymarket.com",
            chain_id=137,
            key=operator_private_key,
            signature_type=2  # EOA signature type
        )
        
        # Derive API credentials from the private key
        # Use derive_api_key() which works for registered accounts
        api_creds = client.derive_api_key()
        
        logger.info(f"Successfully derived Polymarket credentials for agent")
        
        return {
            "success": True,
            "api_key": api_creds.api_key,
            "api_secret": api_creds.api_secret,
            "api_passphrase": api_creds.api_passphrase,
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
    condition_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get detailed information about a specific prediction market including current prices, outcomes, liquidity, volume, and resolution details.

    Generated from OpenAPI endpoint: GET /markets/{condition_id}

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        condition_id: The unique condition ID of the market (e.g., '0x...' hex string) (optional) Examples: "0x1234567890abcdef1234567890abcdef12345678"

    Returns:
        Dictionary with API response

    Example Usage:
        await get_market(condition_id="0x1234567890abcdef1234567890abcdef12345678")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/markets/{condition_id}"
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
        return {"error": str(e), "endpoint": "/markets/{condition_id}"}


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
    tag: Optional[str] = None
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    List all events on Polymarket. Events group related prediction markets together (e.g., 'US 2024 Presidential Election' event contains multiple markets).

    Generated from OpenAPI endpoint: GET /events

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        limit: Maximum number of events to return (optional, default: 100)
        offset: Offset for pagination (optional, default: 0)
        order: Sort order (optional, default: "volume")
        ascending: Sort in ascending order (optional, default: False)
        active: Filter for active events only (optional, default: True)
        tag: Filter by category tag (optional)

    Returns:
        Dictionary with API response

    Example Usage:
        # Minimal (required params only):
        await list_events()

        # With optional parameters:
        await list_events(
        limit=100,
        offset=0,
        order="volume"
    )

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
            "tag": tag
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
    market_ids: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get current prices and implied probabilities for prediction market outcomes. Prices are between 0-1 representing probability (0.65 = 65% probability).

    Generated from OpenAPI endpoint: GET /prices

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        market_ids: Comma-separated list of market condition IDs to get prices for (optional) Examples: "0x123...,0x456..."

    Returns:
        Dictionary with API response

    Example Usage:
        await get_prices(market_ids="0x123...,0x456...")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/prices"
        params = {
            "market_ids": market_ids
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
    token_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the order book for a specific market token showing bid and ask orders with prices and sizes.

    Generated from OpenAPI endpoint: GET /book

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get the order book for (YES or NO outcome token) (optional)

    Returns:
        Dictionary with API response

    Example Usage:
        await get_orderbook(token_id="example")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/book"
        params = {
            "token_id": token_id
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
    token_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the midpoint price for a market token (average between best bid and ask).

    Generated from OpenAPI endpoint: GET /midpoint

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get midpoint price for (optional)

    Returns:
        Dictionary with API response

    Example Usage:
        await get_midpoint(token_id="example")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/midpoint"
        params = {
            "token_id": token_id
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
    token_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the bid-ask spread for a market token showing the difference between best bid and best ask prices.

    Generated from OpenAPI endpoint: GET /spread

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get spread for (optional)

    Returns:
        Dictionary with API response

    Example Usage:
        await get_spread(token_id="example")

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/spread"
        params = {
            "token_id": token_id
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
    limit: int = 100,
    before: Optional[str] = None,
    after: Optional[str] = None
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Get recent trade history for a market showing executed transactions with prices, sizes, and timestamps.

    Generated from OpenAPI endpoint: GET /trades

    Args:
        context: MCP context (auto-injected by framework, not user-provided)
        token_id: The token ID to get trades for (optional)
        limit: Maximum number of trades to return (optional, default: 100)
        before: Get trades before this trade ID (for pagination) (optional)
        after: Get trades after this trade ID (for pagination) (optional)

    Returns:
        Dictionary with API response

    Example Usage:
        # Minimal (required params only):
        await get_trades(token_id="example")

        # With optional parameters:
        await get_trades(token_id="example", limit=100)

        Note: 'context' parameter is auto-injected by MCP framework
    """
    # Payment already verified by @require_payment_for_tool decorator
    # Get API key using helper (handles request.state fallback)
    api_key = get_active_api_key(context)

    try:
        url = f"https://gamma-api.polymarket.com/trades"
        params = {
            "token_id": token_id,
            "limit": limit,
            "before": before,
            "after": after
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
    operator_private_key: str,
    token_id: str,
    side: str,
    price: float,
    size: float,
    order_type: str = "GTC",
    expiration: Optional[int] = None
) -> Dict[str, Any]:
    """
    [TRADING] Create a new order to buy or sell prediction market shares.
    
    Credentials are derived automatically from the private key.
    Trade executes on agent's Polymarket account with their funds.

    Args:
        context: MCP context (auto-injected by framework)
        operator_private_key: Agent's Ethereum/Polygon private key (0x prefixed)
        token_id: The token ID to trade (outcome token address)
        side: Order side - "BUY" or "SELL"
        price: Limit price for the order (0-1 range for probability)
        size: Size of the order in USDC
        order_type: Order type - "GTC" (Good Till Cancelled), "FOK" (Fill or Kill), "GTD" (Good Till Date)
        expiration: Expiration timestamp for GTD orders (Unix seconds)

    Returns:
        Dictionary with order details or error

    Example Usage:
        await create_order(
            operator_private_key="0x...",
            token_id="0x...",
            side="BUY",
            price=0.65,
            size=10.0
        )
    """
    try:
        # Create authenticated client (derives credentials internally)
        client = create_authenticated_clob_client(operator_private_key)
        
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
    operator_private_key: str,
    order_id: str
) -> Dict[str, Any]:
    """
    [TRADING] Cancel an open order by its order ID.
    
    Credentials are derived automatically from the private key.

    Args:
        context: MCP context (auto-injected by framework)
        operator_private_key: Agent's Ethereum/Polygon private key (0x prefixed)
        order_id: The unique order ID to cancel

    Returns:
        Dictionary with cancellation result
    """
    try:
        # Create authenticated client (derives credentials internally)
        client = create_authenticated_clob_client(operator_private_key)
        
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
    operator_private_key: str,
    market: Optional[str] = None,
    asset_id: Optional[str] = None,
    state: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Get all orders for the agent's account.
    
    Credentials are derived automatically from the private key.

    Args:
        context: MCP context (auto-injected by framework)
        operator_private_key: Agent's Ethereum/Polygon private key (0x prefixed)
        market: Filter by market condition ID (optional)
        asset_id: Filter by asset/token ID (optional)
        state: Filter by order state - "open", "matched", "cancelled" (optional)

    Returns:
        List of orders
    """
    try:
        # Create authenticated client (derives credentials internally)
        client = create_authenticated_clob_client(operator_private_key)
        
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
    operator_private_key: str,
    market: Optional[str] = None,
    asset_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Cancel all open orders for the agent's account.
    
    Credentials are derived automatically from the private key.

    Args:
        context: MCP context (auto-injected by framework)
        operator_private_key: Agent's Ethereum/Polygon private key (0x prefixed)
        market: Optional market condition ID to cancel orders for
        asset_id: Optional asset/token ID to cancel orders for

    Returns:
        Dictionary with cancellation result
    """
    try:
        # Create authenticated client (derives credentials internally)
        client = create_authenticated_clob_client(operator_private_key)
        
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
    description="[TRADING - REQUIRES AGENT CREDENTIALS] Get USDC ba"

)
async def get_balance(
    context: Context,
    operator_private_key: str
) -> Dict[str, Any]:
    """
    [TRADING] Get USDC balance for the agent's Polymarket account.
    
    Credentials are derived automatically from the private key.

    Args:
        context: MCP context (auto-injected by framework)
        operator_private_key: Agent's Ethereum/Polygon private key (0x prefixed)

    Returns:
        Dictionary with balance information
    """
    try:
        # Create authenticated client (derives credentials internally)
        client = create_authenticated_clob_client(operator_private_key)
        
        # Get balance
        balance = client.get_balance_allowance()
        
        return {
            "success": True,
            "balance": balance,
            "message": "Balance retrieved successfully"
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
    operator_private_key: str,
    market: Optional[str] = None
) -> Dict[str, Any]:
    """
    [TRADING] Get all open positions for the agent's account.
    
    Credentials are derived automatically from the private key.

    Args:
        context: MCP context (auto-injected by framework)
        operator_private_key: Agent's Ethereum/Polygon private key (0x prefixed)
        market: Optional market condition ID to filter positions

    Returns:
        Dictionary with positions information
    """
    try:
        # Create authenticated client (derives credentials internally)
        client = create_authenticated_clob_client(operator_private_key)
        
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
        Dictionary with API response

    Example Usage:
        await get_tags()
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
    
    # Add health check endpoint (bypasses middleware)
    @app.route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        """Health check endpoint for container orchestration."""
        return JSONResponse(
            content={
                "status": "healthy",
                "service": "polymarket-api-mcp-server",
                "timestamp": datetime.now().isoformat()
            }
        )
    logger.info("✅ Added /health endpoint")
    
    return app

if __name__ == "__main__":
    logger.info("="*80)
    logger.info(f"Starting Polymarket API MCP Server")
    logger.info("="*80)
    logger.info("Architecture:")
    logger.info("  1. D402PaymentMiddleware intercepts requests")
    logger.info("     - Checks payment → HTTP 402 if missing")
    logger.info("  2. FastMCP processes valid requests with tool decorators")
    logger.info("="*80)
    
    # Create app with middleware
    app = create_app_with_middleware()
    
    # Run with uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
    )
