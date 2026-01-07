# Polymarket API MCP Server

This is an MCP (Model Context Protocol) server that provides access to the Polymarket API API. It enables AI agents and LLMs to interact with Polymarket API through standardized tools.

## Features

- 🔧 **MCP Protocol**: Built on the Model Context Protocol for seamless AI integration
- 🌐 **Full API Access**: Provides tools for interacting with Polymarket API endpoints
- 🐳 **Docker Support**: Easy deployment with Docker and Docker Compose
- ⚡ **Async Operations**: Built with FastMCP for efficient async handling

## API Documentation

- **Polymarket API Website**: [https://gamma-api.polymarket.com](https://gamma-api.polymarket.com)
- **API Documentation**: [https://docs.polymarket.com/](https://docs.polymarket.com/)

## Available Tools

This server provides the following tools:

- **`example_tool`**: Placeholder tool (to be implemented)

*Note: Replace `example_tool` with actual Polymarket API API tools based on the documentation.*

## Installation

### Using Docker (Recommended)

1. Clone this repository:
   ```bash
   git clone https://github.com/Traia-IO/polymarket-api-mcp-server.git
   cd polymarket-api-mcp-server
   ```

2. Run with Docker:
   ```bash
   ./run_local_docker.sh
   ```

### Using Docker Compose

1. Create a `.env` file with your configuration:
   ```env
PORT=8000
   ```

2. Start the server:
   ```bash
   docker-compose up
   ```

### Manual Installation

1. Install dependencies using `uv`:
   ```bash
   uv pip install -e .
   ```

2. Run the server:
   ```bash
uv run python -m server
   ```

## Usage

### Health Check

Test if the server is running:
```bash
python mcp_health_check.py
```

### Using with CrewAI

```python
from traia_iatp.mcp.traia_mcp_adapter import create_mcp_adapter

# Connect to the MCP server
with create_mcp_adapter(
    url="http://localhost:8000/mcp/"
) as tools:
    # Use the tools
    for tool in tools:
        print(f"Available tool: {tool.name}")
        
    # Example usage
    result = await tool.example_tool(query="test")
    print(result)
```


## Development

### Testing the Server

1. Start the server locally
2. Run the health check: `python mcp_health_check.py`
3. Test individual tools using the CrewAI adapter

### Adding New Tools

To add new tools, edit `server.py` and:

1. Create API client functions for Polymarket API endpoints
2. Add `@mcp.tool()` decorated functions
3. Update this README with the new tools
4. Update `deployment_params.json` with the tool names in the capabilities array

## Deployment

### Deployment Configuration

The `deployment_params.json` file contains the deployment configuration for this MCP server:

```json
{
  "github_url": "https://github.com/Traia-IO/polymarket-api-mcp-server",
  "mcp_server": {
    "name": "polymarket-api-mcp",
    "description": "Polymarket prediction market api - access market data, prices, probabilities, and trading for prediction markets",
    "server_type": "streamable-http",
"capabilities": [
      // List all implemented tool names here
      "example_tool"
    ]
  },
  "deployment_method": "cloud_run",
  "gcp_project_id": "traia-mcp-servers",
  "gcp_region": "us-central1",
  "tags": ["polymarket api", "api"],
  "ref": "main"
}
```

**Important**: Always update the `capabilities` array when you add or remove tools!

### Google Cloud Run

This server is designed to be deployed on Google Cloud Run. The deployment will:

1. Build a container from the Dockerfile
2. Deploy to Cloud Run with the specified configuration
3. Expose the `/mcp` endpoint for client connections

## Environment Variables

- `PORT`: Server port (default: 8000)
- `STAGE`: Environment stage (default: MAINNET, options: MAINNET, TESTNET)
- `LOG_LEVEL`: Logging level (default: INFO)

## Troubleshooting

1. **Server not starting**: Check Docker logs with `docker logs <container-id>`
2. **Connection errors**: Ensure the server is running on the expected port3. **Tool errors**: Check the server logs for detailed error messages

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement new tools or improvements
4. Update the README and deployment_params.json
5. Submit a pull request

## License

[MIT License](LICENSE)