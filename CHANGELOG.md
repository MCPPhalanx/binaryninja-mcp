# Changelog

## v0.3.0

### Major Changes

- Now the **Start/Stop Server** button in UI actually worked!!
- Added client option `--retry-interval` to improve connection reliability
- `binaryninja-mcp install-api` now works in uv, previously you need a
  `--install-on-pyenv` flag, since uv is _the_ project management tool for the
  MCP community, this flag is now set by default, and could be disabled by
  `--install-on-usersite`

### Fixes

- Fixed compatibility issues with ExceptionGroup imports
- Fixed resource tools functionality
- Fixed ClientSession interference with STDIO clients

### Improvements

- Implemented SSEServerThread for correct server lifecycle management
- Refactored server implementation with FastMCP
- Improved error handling using FastMCP error handling system
- Updated project metadata
- Enhanced documentation in README

### Development Changes

- Replaced Starlette with Hypercorn for improved server performance
- Added test cases for MCP Server with snapshot testing
- Removed pytest dependency from release workflow and smoke tests
- Added workflow permissions for GitHub release creation
- Added isort to ruff configuration
- Improved code organization with better import sorting
- Added test snapshots for MCP tools

## v0.2.2

### Development Changes

- Added GitHub release action
- Moved Binary Ninja configuration to conftest
- Added pre-commit hooks for code quality

## v0.2.1

### Fixes

- Fixed disassembly tool functionality
- Resolved log module import issues when BinaryNinja is not installed
- Improved error handling and logging mechanisms
- Fixed debug logs in BinaryNinja integration

### Improvements

- Ensured CLI can run without BinaryNinja being installed
- Updated development instructions
- Added warning for BinaryNinja API not being installed
- Optimized logging processes

### Development Changes

- Added Continuous Integration (CI) workflow
- Added smoke test suite
- Reformatted entire codebase for improved accessibility
- Integrated ruff for code formatting and linting
- Enhanced test infrastructure (creating binaryview fixture separately for each
  test case)
- Updated test snapshots
- Added dependencies for release workflow

## v0.2.0

Initial Release. The following tools are available.

- `rename_symbol`: Rename a function or a data variable
- `pseudo_c`: Get pseudo C code of a specified function
- `pseudo_rust`: Get pseudo Rust code of a specified function
- `high_level_il`: Get high level IL of a specified function
- `medium_level_il`: Get medium level IL of a specified function
- `disassembly`: Get disassembly of function or specified range
- `update_analysis_and_wait`: Update analysis for the binary and wait for
  completion
