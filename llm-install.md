# MCP Server Installation Guide

This simplified installation guide is designed to be machine-readed for Clients
like Cline to automate the MCP server setup.

Do not clone the git repository,

# Installation Steps

1. Prompt user to open binary ninja and install `Another MCP Server` from plugin
   manager, then open a binaryview after plugin installed, add a confirmation
   step.
2. Add the following server configuration to mcp settings JSON
   ```json
   {
     "mcpServers": {
       "binaryninja": {
         "url": "http://127.0.0.1:7000/sse",
         "disabled": false,
         "autoApprove": []
       }
     }
   }
   ```
3. Done! get a list of tools and call `list_filename` tool to check if the
   server works correctly.
