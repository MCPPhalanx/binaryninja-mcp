# binaryninja-mcp

MCP Server for Binary Ninja

# Installation

## Server Setup

There are two ways to run the MCP server:

1. **Binary Ninja UI Plugin**:
   - Install the plugin via Binary Ninja's plugin manager
   - The MCP server will start automatically when first file is loaded.
     - Auto start is configurable via `Settings - MCP Server - Auto Start`
     - Listen port is configurable via `Settings - MCP Server - Server port number`
   - All opened files are exposed to separate resources, see [Available Resources](README.md#available-resources) section below

2. **Binary Ninja Headless Mode**:
   ```bash
   uvx binaryninja-mcp server <filename> [filename]...
   ```
   - `filename` could be any binary files or BNDB, like in UI mode, all opened files are available to the MCP client.
   - Server runs on default port 7000
   - Use `--port` flag to specify a different port


## MCP Client Setup

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

# Available Tools for MCP Clients

The MCP server provides the following tools:

- `rename_symbol`: Rename a function or a data variable
- `pseudo_c`: Get pseudo C code of a specified function
- `pseudo_rust`: Get pseudo Rust code of a specified function
- `high_level_il`: Get high level IL of a specified function
- `medium_level_il`: Get medium level IL of a specified function
- `disassembly`: Get disassembly of a function or specified range
- `update_analysis_and_wait`: Update analysis for the binary and wait for completion

# Available Resources for MCP Clients

MCP Resources can be accessed via URIs in the format:
`binaryninja://{filename}/{resource_type}`

The server provides these resource types for each binary:

- `triage_summary`: Basic information from BinaryNinja Triage view
- `imports`: Dictionary of imported symbols/functions
- `exports`: Dictionary of exported symbols/functions
- `segments`: List of memory segments
- `sections`: List of binary sections
- `strings`: List of strings found in the binary
- `functions`: List of functions
- `data_variables`: List of data variables

# Development

[uv](https://github.com/astral-sh/uv) is the recommanded package management tool for this project.

## Clone directory to Binary Ninja Plugin Directory

```powershell
git clone https://github.com/MCPPhalanx/binaryninja-mcp.git "${env:APPDATA}\Binary Ninja\plugins\MCPPhalanx_binaryninja_mcp"
```

## Setup Python Environment

Binary Ninja API must be installed into virtualenv manually.

```bash
uv venv
uv sync
# install binaryninja API
python $env:LOCALAPPDATA\Programs\Vector35\BinaryNinja\scripts\install_api.py
# check API is correctly installed
uv run python -c 'import binaryninja as bn; print(f"ui_enabled={bn.core_ui_enabled()}")'
```

## Setup MCP Client for Development

For MCP clients with stdio transport like Claude Desktop, change working directory to development folder.

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

SSE-enabled MCP clients can connect using: `http://localhost:7000/sse`

## Build
```bash
uv build
```

## Test
```bash
pytest
# To update test snapshots:
pytest --snapshot-update
```

## Version Bump

The PyPI package version is automatically derived from Binary Ninja's `plugin.json` (using package.json format), maintaining version consistency between the BN plugin and PyPI package.

```bash
# bump alpha version
uvx hatch version a

# bump release version
uvx hatch version minor,rc
uvx hatch version release
```
See: [Versioning - Hatch](https://hatch.pypa.io/1.12/version/)

## Release
```bash
uv publish
```

# License
[Apache 2.0](LICENSE)
