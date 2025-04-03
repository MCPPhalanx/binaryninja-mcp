import click
import uvicorn
import logging
from binaryninja_mcp.server import create_mcp_server, create_sse_app
from binaryninja_mcp.consts import DEFAULT_PORT
from binaryninja_mcp.utils import disable_binaryninja_user_plugins, find_binaryninja_path

@click.group()
def cli():
    """MCP CLI tool for Binary Ninja"""
    pass

@cli.command()
@click.option('--listen-host', default="localhost", help='SSE bind address')
@click.option('-p', '--listen-port', default=DEFAULT_PORT, help='SSE server port')
@click.argument('filename')
def server(listen_host, listen_port, filename):
    """Start an MCP server for the given binary file"""
    from binaryninja import load

    logging.basicConfig(level=logging.INFO)

    disable_binaryninja_user_plugins()

    # Load the binary view
    bv = load(filename)
    if not bv:
        click.echo(f"Failed to load binary: {filename}", err=True)
        return

    mcp = create_mcp_server([bv])

    # Run SSE server
    click.echo(f"Starting MCP server for {filename} on port {listen_port}")

    app = create_sse_app(mcp)
    uvicorn.run(app, host=listen_host, port=listen_port, timeout_graceful_shutdown=2)

@cli.command()
@click.option('--host', default='localhost', help='SSE server host')
@click.option('--port', default=DEFAULT_PORT, help='SSE server port')
def client(host, port):
    """Connect to an MCP SSE server and relay to stdio"""
    logging.basicConfig(level=logging.INFO)

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
            click.echo(f"Error: {message}", err=True)
            return

    async def run_client():
        # Connect to SSE server
        url = f"http://{host}:{port}/sse"
        click.echo(f"Connecting to MCP server at {url}", err=True)

        # Create stdio server to relay messages
        async with stdio_server() as (stdio_read, stdio_write):
            # Connect to SSE server
            async with sse_client(url) as (sse_read, sse_write):
                # Create client session
                async with ClientSession(
                    sse_read, sse_write, message_handler=message_handler
                ) as session:
                    click.echo(f"Connected to MCP server at {host}:{port}", err=True)

                    # Create a proxy to relay messages between stdio and SSE
                    # Forward messages from stdio to SSE
                    async def forward_stdio_to_sse():
                        try:
                            while True:
                                message = await stdio_read.receive()
                                await sse_write.send(message)
                        except Exception as e:
                            click.echo(f"Error forwarding stdio to SSE: {e}", err=True)

                    # Forward messages from SSE to stdio
                    async def forward_sse_to_stdio():
                        try:
                            while True:
                                message = await sse_read.receive()
                                await stdio_write.send(message)
                        except Exception as e:
                            click.echo(f"Error forwarding SSE to stdio: {e}", err=True)

                    # Run both forwarding tasks concurrently
                    async with anyio.create_task_group() as tg:
                        tg.start_soon(forward_stdio_to_sse)
                        tg.start_soon(forward_sse_to_stdio)

    try:
        # Use anyio.run with trio backend as in the reference code
        anyio.run(run_client, backend="trio")
    except KeyboardInterrupt:
        click.echo("\nDisconnected", err=True)
    except Exception as e:
        click.echo(f"Connection error: {e}", err=True)

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
        click.echo("Could not find Binary Ninja install directory, please provide the path via --binja-path", err=True)
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
        click.echo("Operation failed", err=True)
        raise SystemExit(1)
    click.echo("Operation succeeded")

if __name__ == '__main__':
    cli()
