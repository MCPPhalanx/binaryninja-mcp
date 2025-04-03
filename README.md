# binaryninja-mcp
MCP Server for Binary Ninja

## Installation

### Server Setup

There are two ways to run the MCP server:

1. **Binary Ninja Plugin**:
   - Install the plugin via Binary Ninja's plugin manager
   - The MCP server will start automatically when first file is loaded
     - auto start configurable via `Settings - MCP Server - Auto Start`
   - All opened files are exposed to separate resources, see [Available Resources](README.md#available-resources) section below

2. **Binary Ninja Headless Mode**:
   ```bash
   uvx binaryninja-mcp server <filename.exe-elf-bndb> [filename]...
   ```
   - Server runs on default port 7000
   - Use `--port` flag to specify a different port
   - This setup

### MCP Client Setup

1. **Claude Desktop (stdio relay client)**:
   Configure the client to connect via stdio transport using built-in relay.

   ```json
   {
       "mcpServers": {
           "binaryninja": {
               "command": "uvx",
               "args": [
                   "binaryninja-mcp", "client"
               ]
           }
       }
   }
   ```


2. **Cherry Studio**:
   - **SSE endpoint** (recommanded): URL: `http://localhost:7000/sse`
   - **stdio client**:
      - Command: `uvx`
      - Arguments:
        ```
        binaryninja-mcp
        client
        ```

## Available Tools

The MCP server provides the following tools:

- `rename_symbol`: Rename a function or a data variable
- `pseudo_c`: Get pseudo C code of a specified function
- `pseudo_rust`: Get pseudo Rust code of a specified function
- `high_level_il`: Get high level IL of a specified function
- `medium_level_il`: Get medium level IL of a specified function
- `disassembly`: Get disassembly of a function or specified range
- `update_analysis_and_wait`: Update analysis for the binary and wait for completion

## Available Resources

The server provides these resource types for each binary:

- `triage_summary`: Basic information from BinaryNinja Triage view
- `imports`: Dictionary of imported symbols/functions
- `exports`: Dictionary of exported symbols/functions
- `segments`: List of memory segments
- `sections`: List of binary sections
- `strings`: List of strings found in the binary
- `functions`: List of functions
- `data_variables`: List of data variables

Resources can be accessed via URIs in the format:
`binaryninja://{filename}/{resource_type}`

## Example Usage

```python
# Connect to server and list available tools
import mcp

client = mcp.Client()
tools = client.list_tools()
print("Available tools:", [t.name for t in tools])

# Get pseudo C for a function
result = client.call_tool("pseudo_c", {
    "filename": "sample.elf",
    "address": "0x401000"
})
print(result)
```


## Development

### Setup Environment

Binary Ninja API must be installed into virtualenv manually.

```bash
uv venv
uv sync
# install binaryninja API
python $env:LOCALAPPDATA\Programs\Vector35\BinaryNinja\scripts\install_api.py
# check API is correctly installed
uv run python -c 'import binaryninja as bn; print(f"ui_enabled={bn.core_ui_enabled()}")'
```

### MCP Client Dev Setup

```json
{
  "mcpServers": {
    "binaryninja": {
      "command": "uv",
      "args": [
        "--directory", "C:/path/to/binaryninja-mcp",
        "run",
        "binaryninja-mcp", "client"
      ]
    }
  }
}
```

### Build
```bash
uv build
```

### Test
```bash
pytest
# To update test snapshots:
pytest --snapshot-update
```

### Release
```bash
uv publish
```

## License
[Apache 2.0](LICENSE)
