# Changelog

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
