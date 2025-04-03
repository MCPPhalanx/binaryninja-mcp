import asyncio
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Any, Iterable

import binaryninja as bn
from binaryninja_mcp.log import setup_logging
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from mcp.types import Tool, Resource, ResourceTemplate, TextContent
from pydantic import AnyUrl

from binaryninja_mcp.consts import DEFAULT_PORT, TEST_BINARY_PATH_ELF
from binaryninja_mcp.resources import MCPResource
from binaryninja_mcp.tools import MCPTools
from binaryninja_mcp.utils import bv_name, disable_binaryninja_user_plugins

logger = logging.getLogger(__package__)


@dataclass
class BNContext:
    """Context holding loaded BinaryViews with automatic name deduplication"""
    bvs: Dict[str, bn.BinaryView] = field(default_factory=dict)

    def add_bv(self, bv: bn.BinaryView, name: Optional[str] = None) -> str:
        """Add a BinaryView to the context with automatic name deduplication

        Args:
            bv: The BinaryView to add
            name: Optional name to use (defaults to filename)

        Returns:
            The name used for the BinaryView
        """
        if name is None:
            name = bv_name(bv)

        # Sanitize name for URL usage
        invalid_chars = '/\\:*?"<>| '
        for c in invalid_chars:
            name = name.replace(c, '_')
        name = name.strip('_.')
        if not name:
            name = 'unnamed'

        # Deduplicate name if needed
        base_name = name
        counter = 1
        while name in self.bvs:
            name = f"{base_name}_{counter}"
            counter += 1

        self.bvs[name] = bv
        logger.debug("Added BinaryView %s as '%s'", bv, name)
        return name

    def get_bv(self, name: str) -> Optional[bn.BinaryView]:
        """Get a BinaryView by name

        Args:
            name: The name of the BinaryView

        Returns:
            The BinaryView if found, None otherwise
        """
        logger.debug("Looking up BinaryView: %s", name)
        bv = self.bvs.get(name)
        if not bv:
            logger.warning("BinaryView not found: %s", name)
        return bv


@asynccontextmanager
async def lifespan(server: Server) -> AsyncIterator[BNContext]:
    """Application lifecycle manager with initial BinaryViews"""
    context = BNContext()

    # Add initial BinaryViews from server configuration
    for bv in getattr(server, 'initial_bvs', []):
        context.add_bv(bv)

    try:
        yield context
    finally:
        logger.info("Cleaning up BNContext")
        if not bn.core_ui_enabled():
            # TODO: Cleanup resources
            pass


def create_mcp_server(initial_bvs: Optional[List[bn.BinaryView]] = None) -> Server:
    """Initialize MCP server with optional initial BinaryViews

    Args:
        initial_bvs: Optional list of BinaryViews to initialize the server with

    Returns:
        Configured MCP server instance
    """
    server = Server(
        name="BinaryNinja",
        version="1.0.0",
        instructions="MCP server for Binary Ninja analysis",
        lifespan=lifespan
    )

    # Store initial BinaryViews for use in lifespan
    server.initial_bvs = initial_bvs or []

    # Register resource handlers
    @server.list_resources()
    async def list_resources() -> List[Resource]:
        """List all available resources"""
        bnctx: BNContext = server.request_context.lifespan_context
        resources = []

        # Add a resource for each BinaryView
        for name in bnctx.bvs:
            resources.append(Resource(
                uri=f"binaryninja://{name}/triage_summary",
                name=f"Triage Summary for {name}",
                description="Basic information as shown in BinaryNinja Triage view",
                mimeType="application/json"
            ))

            # Add other resource types
            for resource_type in [
                "imports", "exports", "segments", "sections",
                "strings", "functions", "data_variables"
            ]:
                resources.append(Resource(
                    uri=f"binaryninja://{name}/{resource_type}",
                    name=f"{resource_type.capitalize()} for {name}",
                    description=f"List of {resource_type} in the binary",
                    mimeType="application/json"
                ))
        logger.debug("Listing available resources, %d bvs => %d resources", len(bnctx.bvs), len(resources))

        return resources

    @server.list_resource_templates()
    async def list_resource_templates() -> List[ResourceTemplate]:
        """List all available resource templates"""
        logger.debug("Listing resource templates")
        return [
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/triage_summary",
                name="Triage Summary",
                description="Basic information as shown in BinaryNinja Triage view",
                mimeType="application/json"
            ),
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/imports",
                name="Imports",
                description="Dictionary of imported symbols or functions with properties",
                mimeType="application/json"
            ),
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/exports",
                name="Exports",
                description="Dictionary of exported symbols or functions with properties",
                mimeType="application/json"
            ),
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/segments",
                name="Segments",
                description="List of memory segments",
                mimeType="application/json"
            ),
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/sections",
                name="Sections",
                description="List of binary sections",
                mimeType="application/json"
            ),
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/strings",
                name="Strings",
                description="List of strings found in the binary",
                mimeType="application/json"
            ),
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/functions",
                name="Functions",
                description="List of functions",
                mimeType="application/json"
            ),
            ResourceTemplate(
                uriTemplate="binaryninja://{filename}/data_variables",
                name="Data Variables",
                description="List of data variables",
                mimeType="application/json"
            )
        ]

    @server.read_resource()
    async def read_resource(uri: AnyUrl) -> Iterable[ReadResourceContents]:
        """Read a resource by URI"""
        logger.debug("Reading resource: %s", uri)
        bnctx: BNContext = server.request_context.lifespan_context

        # Parse the URI
        uri_str = str(uri)
        if not uri_str.startswith("binaryninja://"):
            raise ValueError(f"Invalid URI scheme: {uri_str}")

        # Extract filename and resource type
        path = uri_str[len("binaryninja://"):]
        parts = path.split("/")

        if len(parts) != 2:
            raise ValueError(f"Invalid URI format: {uri_str}")

        filename, resource_type = parts

        # Get the BinaryView
        bv = bnctx.get_bv(filename)
        if not bv:
            raise ValueError(f"BinaryView not found: {filename}")

        # Create resource handler
        resource = MCPResource(bv)

        # Call the appropriate method based on resource type
        if resource_type == "triage_summary":
            data = resource.triage_summary()
        elif resource_type == "imports":
            data = resource.imports()
        elif resource_type == "exports":
            data = resource.exports()
        elif resource_type == "segments":
            data = resource.segments()
        elif resource_type == "sections":
            data = resource.sections()
        elif resource_type == "strings":
            data = resource.strings()
        elif resource_type == "functions":
            data = resource.functions()
        elif resource_type == "data_variables":
            data = resource.data_variables()
        else:
            raise ValueError(f"Unknown resource type: {resource_type}")

        # Return the data as JSON
        return [ReadResourceContents(
            content=json.dumps(data, indent=2),
            mime_type="application/json"
        )]

    # Register tool handlers
    @server.list_tools()
    async def list_tools() -> List[Tool]:
        """List all available tools"""
        logger.debug("Listing available tools")
        return [
            Tool(
                name="rename_symbol",
                description="Rename a function or a data variable",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Name of the binary file"
                        },
                        "address": {
                            "type": "string",
                            "description": "Address of the function or data variable (hex string)"
                        },
                        "new_name": {
                            "type": "string",
                            "description": "New name for the symbol"
                        }
                    },
                    "required": ["filename", "address", "new_name"]
                }
            ),
            Tool(
                name="pseudo_c",
                description="Get pseudo C code of a specified function",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Name of the binary file"
                        },
                        "address": {
                            "type": "string",
                            "description": "Address of the function (hex string)"
                        }
                    },
                    "required": ["filename", "address"]
                }
            ),
            Tool(
                name="pseudo_rust",
                description="Get pseudo Rust code of a specified function",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Name of the binary file"
                        },
                        "address": {
                            "type": "string",
                            "description": "Address of the function (hex string)"
                        }
                    },
                    "required": ["filename", "address"]
                }
            ),
            Tool(
                name="high_level_il",
                description="Get high level IL of a specified function",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Name of the binary file"
                        },
                        "address": {
                            "type": "string",
                            "description": "Address of the function (hex string)"
                        }
                    },
                    "required": ["filename", "address"]
                }
            ),
            Tool(
                name="medium_level_il",
                description="Get medium level IL of a specified function",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Name of the binary file"
                        },
                        "address": {
                            "type": "string",
                            "description": "Address of the function (hex string)"
                        }
                    },
                    "required": ["filename", "address"]
                }
            ),
            Tool(
                name="disassembly",
                description="Get disassembly of a function or specified range",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Name of the binary file"
                        },
                        "address": {
                            "type": "string",
                            "description": "Address to start disassembly (hex string)"
                        },
                        "length": {
                            "type": "integer",
                            "description": "Optional length of bytes to disassemble"
                        }
                    },
                    "required": ["filename", "address"]
                }
            ),
            Tool(
                name="update_analysis_and_wait",
                description="Update analysis for the binary and wait for it to complete",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Name of the binary file"
                        }
                    },
                    "required": ["filename"]
                }
            )
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> Iterable[TextContent]:
        """Call a tool by name with arguments"""
        logger.debug("Calling tool: %s with args: %s", name, arguments)
        bnctx: BNContext = server.request_context.lifespan_context

        # Validate required arguments
        if "filename" not in arguments:
            return [TextContent(
                type="text",
                text="Error: Missing required argument 'filename'"
            )]

        # Get the BinaryView
        filename = arguments["filename"]
        bv = bnctx.get_bv(filename)
        if not bv:
            return [TextContent(
                type="text",
                text=f"Error: BinaryView not found: {filename}"
            )]

        # Create tool handler
        tools = MCPTools(bv)

        # Call the appropriate method based on tool name
        if name == "rename_symbol":
            if "address" not in arguments or "new_name" not in arguments:
                return [TextContent(
                    type="text",
                    text="Error: Missing required arguments 'address' and/or 'new_name'"
                )]
            return tools.rename_symbol(arguments["address"], arguments["new_name"])

        elif name == "pseudo_c":
            if "address" not in arguments:
                return [TextContent(
                    type="text",
                    text="Error: Missing required argument 'address'"
                )]
            return tools.pseudo_c(arguments["address"])

        elif name == "pseudo_rust":
            if "address" not in arguments:
                return [TextContent(
                    type="text",
                    text="Error: Missing required argument 'address'"
                )]
            return tools.pseudo_rust(arguments["address"])

        elif name == "high_level_il":
            if "address" not in arguments:
                return [TextContent(
                    type="text",
                    text="Error: Missing required argument 'address'"
                )]
            return tools.high_level_il(arguments["address"])

        elif name == "medium_level_il":
            if "address" not in arguments:
                return [TextContent(
                    type="text",
                    text="Error: Missing required argument 'address'"
                )]
            return tools.medium_level_il(arguments["address"])

        elif name == "disassembly":
            if "address" not in arguments:
                return [TextContent(
                    type="text",
                    text="Error: Missing required argument 'address'"
                )]
            length = arguments.get("length")
            return tools.disassembly(arguments["address"], length)

        elif name == "update_analysis_and_wait":
            return tools.update_analysis_and_wait()

        else:
            return [TextContent(
                type="text",
                text=f"Error: Unknown tool: {name}"
            )]

    return server


def create_sse_app(server: Server):
    """Create a Starlette application for SSE transport

    Args:
        server: The MCP server instance

    Returns:
        A Starlette application configured for SSE transport
    """
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await server.run(
                streams[0], streams[1], server.create_initialization_options()
            )

    starlette_app = Starlette(
        debug=True,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )

    return starlette_app

async def run_stdio_server(initial_bvs: Optional[List[bn.BinaryView]] = None):
    """Run the MCP server over stdio

    Args:
        initial_bvs: Optional list of BinaryViews to initialize the server with
    """
    server = create_mcp_server(initial_bvs)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    """
    uv add anyio --dev
    uv run ./src/binaryninja_mcp/server.py
    """

    disable_binaryninja_user_plugins()
    bv = bn.load(TEST_BINARY_PATH_ELF, update_analysis=False)
    setup_logging(logging.DEBUG)
    server = create_mcp_server([bv])

    # if False:
    # else:
    #     server = create_mcp_server()
    #     app = server.sse_app
    transport = "stdio"

    if transport == "sse":
        import uvicorn
        starlette_app = create_sse_app(server)
        uvicorn.run(starlette_app, host="localhost", port=DEFAULT_PORT, timeout_graceful_shutdown=2)
    else:
        from mcp.server.stdio import stdio_server

        async def arun():
            async with stdio_server() as streams:
                await server.run(
                    streams[0], streams[1], server.create_initialization_options()
                )

        import anyio

        anyio.run(arun)

# launched by `mcp dev server.py`
elif __name__ == "server_module":
    print("loading server module")
    # bv = bn.load(TEST_BINARY_PATH_ELF, update_analysis=False)
    server = create_mcp_server()
