import click
from exceptiongroup import ExceptionGroup
import uvicorn
import logging
from binaryninja_mcp.server import create_mcp_server, create_sse_app
from binaryninja_mcp.consts import DEFAULT_PORT
from binaryninja_mcp.utils import disable_binaryninja_user_plugins, find_binaryninja_path
from binaryninja_mcp.log import setup_logging

logger = logging.getLogger(__name__)

@click.group()
@click.option('-v', '--verbose', count=True, help='Enable verbose debug logging')
def cli(verbose):
    """MCP CLI tool for Binary Ninja"""
    log_level, third_party_log_level = {
        0: (logging.INFO, logging.WARNING),
        1: (logging.DEBUG, logging.WARNING),
    }.get(verbose, (logging.DEBUG, logging.DEBUG))
    setup_logging(log_level=log_level, third_party_log_level=third_party_log_level)

@cli.command()
@click.option('--listen-host', default="localhost", help='SSE bind address')
@click.option('-p', '--listen-port', default=DEFAULT_PORT, help='SSE server port')
@click.argument('filename')
def server(listen_host, listen_port, filename):
    """Start an MCP server for the given binary file"""
    from binaryninja import load

    disable_binaryninja_user_plugins()

    # Load the binary view
    bv = load(filename)
    if not bv:
        logger.error("Failed to load binary: %s", filename)
        return

    mcp = create_mcp_server([bv])

    # Run SSE server
    logger.info("Starting MCP server for %s on port %d", filename, listen_port)

    app = create_sse_app(mcp)
    uvicorn.run(app, host=listen_host, port=listen_port, timeout_graceful_shutdown=2)

@cli.command()
@click.option('--host', default='localhost', help='SSE server host')
@click.option('--port', default=DEFAULT_PORT, help='SSE server port')
def client(host, port):
    """Connect to an MCP SSE server and relay to stdio"""

    import anyio
    from mcp.client.session import ClientSession
    from mcp.client.sse import sse_client
    from mcp.shared.session import RequestResponder
    from mcp.server.stdio import stdio_server
    import mcp.types as types

    async def message_handler(
        message: RequestResponder[types.ServerRequest, types.ClientResult]
        | types.ServerNotification
        | Exception,
    ) -> None:
        if isinstance(message, Exception):
            logger.error("Error: %s", message)
            return

    async def run_client():
        # Connect to SSE server
        url = f"http://{host}:{port}/sse"
        logger.info("Connecting to MCP server at %s", url)
        # Create stdio server to relay messages
        async with stdio_server() as (stdio_read, stdio_write):
            # Connect to SSE server
            async with sse_client(url) as (sse_read, sse_write):
                # Create client session
                async with ClientSession(
                    sse_read, sse_write, message_handler=message_handler
                ) as session:
                    logger.info("Connected to MCP server at %s:%d", host, port)

                    # Create a disconnection event to signal when either connection is broken
                    disconnection_event = anyio.Event()

                    # Create a proxy to relay messages between stdio and SSE
                    # Forward messages from stdio to SSE
                    async def forward_stdio_to_sse():
                        try:
                            while True:
                                message = await stdio_read.receive()
                                await sse_write.send(message)
                        except Exception as e:
                            logger.error("Error forwarding stdio to SSE: %s", e)
                            # Signal disconnection and exit
                            disconnection_event.set()

                    # Forward messages from SSE to stdio
                    async def forward_sse_to_stdio():
                        try:
                            while True:
                                message = await sse_read.receive()
                                await stdio_write.send(message)
                        except Exception as e:
                            logger.error("Error forwarding SSE to stdio: %s", e)
                            # Signal disconnection and exit
                            disconnection_event.set()

                    # Function to wait for disconnection and exit
                    async def wait_for_disconnection():
                        await disconnection_event.wait()
                        # Once disconnection is detected, just return to exit the task group
                        logger.info("Disconnection detected, exiting...")
                        raise SystemExit(0)

                    # Run all tasks concurrently
                    async with anyio.create_task_group() as tg:
                        tg.start_soon(forward_stdio_to_sse)
                        tg.start_soon(forward_sse_to_stdio)
                        tg.start_soon(wait_for_disconnection)

    try:
        # Use anyio.run with trio backend as in the reference code
        anyio.run(run_client, backend="trio")
    except KeyboardInterrupt:
        logger.info("\nDisconnected")
    except ExceptionGroup as eg:
        logger.error("anyio job error: %s", repr(eg.exceptions))
        # Exit with error code
        raise SystemExit(1)
    except Exception as e:
        logger.error("Connection error: %s", e)
        # Exit with error code
        raise SystemExit(1)

@cli.command()
@click.option('--binja-path', type=click.Path(exists=True), help='Custom Binary Ninja install path')
@click.option('--silent', is_flag=True, help='Run in non-interactive mode')
@click.option('--uninstall', is_flag=True, help='Uninstall instead of install')
@click.option('--force', is_flag=True, help='Force installation')
@click.option('--install-on-root', is_flag=True, help='Install to system Python')
@click.option('--install-on-pyenv', is_flag=True, help='Install to pyenv')
def install_api(binja_path, silent, uninstall, force, install_on_root, install_on_pyenv):
    """Install/uninstall Binary Ninja API"""
    install_path = find_binaryninja_path(binja_path)
    if not install_path:
        logger.error("Could not find Binary Ninja install directory, please provide the path via --binja-path")
        raise SystemExit(1)

    install_script = install_path / 'scripts/install_api.py'
    # Import from found script
    import importlib.util
    spec = importlib.util.spec_from_file_location("install_api", install_script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if uninstall:
        result = module.uninstall()
    else:
        result = module.install(
            interactive=not silent,
            on_root=install_on_root,
            on_pyenv=install_on_pyenv,
            force=force
        )

    if not result:
        logger.error("Operation failed")
        raise SystemExit(1)
    logger.info("Operation succeeded")

if __name__ == '__main__':
    cli()
