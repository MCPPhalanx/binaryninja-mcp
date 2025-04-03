from binaryninja.binaryview import BinaryView, BinaryViewType
from binaryninja.log import log_info, log_debug
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from binaryninja.settings import Settings
from binaryninja_mcp.consts import DEFAULT_PORT
from binaryninja_mcp.utils import bv_name
from binaryninja_mcp.server import create_mcp_server, create_sse_app
from typing import Optional, Dict
import threading
import uvicorn

TAG = "MCPServer"
SETTINGS_NAMESPACE = "mcpserver"

class MCPServerPlugin:
    def __init__(self):
        self.bvs: Dict[str, BinaryView] = {}
        self.server_thread: Optional[BackgroundTaskThread] = None
        self.uvicorn_server: Optional[uvicorn.Server] = None
        self.settings = Settings()
        self.register_settings()
        self.load_settings()

    def register_settings(self):
        """Register settings with default values"""
        self.settings.register_group(SETTINGS_NAMESPACE, "MCP Server")
        self.settings.register_setting(
            f"{SETTINGS_NAMESPACE}.listen_host",
            '{"title":"Listen Host","description":"Server bind address","type":"string","default":"localhost"}'
        )
        self.settings.register_setting(
            f"{SETTINGS_NAMESPACE}.listen_port",
            f'{{"title":"Listen Port","description":"Server port number","type":"number","minValue":1,"maxValue":65535,"default":{DEFAULT_PORT}}}'
        )
        self.settings.register_setting(
            f"{SETTINGS_NAMESPACE}.auto_start",
            '{"title":"Auto Start","description":"Start MCP server when the first file is loaded","type":"boolean","default":true}'
        )

    def load_settings(self):
        """Load settings from persistent storage"""
        self.listen_host = self.settings.get_string(f"{SETTINGS_NAMESPACE}.listen_host") or "localhost"
        self.listen_port = int(self.settings.get_string(f"{SETTINGS_NAMESPACE}.listen_port") or DEFAULT_PORT)
        self.auto_start = self.settings.get_string(f"{SETTINGS_NAMESPACE}.auto_start") in {"true", "1"}

    def save_settings(self):
        """Persist current settings"""
        self.settings.set_string(f"{SETTINGS_NAMESPACE}.listen_host", self.listen_host)
        self.settings.set_string(f"{SETTINGS_NAMESPACE}.listen_port", str(self.listen_port))

    def on_binaryview_initial_analysis_completion(self, bv: BinaryView):
        log_info(f"bv={bv} bv.file={bv.file}", TAG)
        name = bv_name(bv)
        self.bvs[name] = bv
        log_info(f"Tracking BinaryView: {name}", TAG)
        if self.auto_start and not self.server_running():
            # Auto-start server on plugin init
            self.start_server()

    def server_running(self) -> bool:
        return bool(self.server_thread and self.server_thread.is_alive())

    def server_control(self, bv: BinaryView):
        if self.server_running():
            self.stop_server()
        else:
            self.start_server()

    def run_server(self):
        """Background task thread entry point"""
        try:
            mcp = create_mcp_server(list(self.bvs.values()))
            app = create_sse_app(mcp)
            config = uvicorn.Config(
                app,
                host=self.listen_host,
                port=self.listen_port,
                # loop="asyncio",
                log_level="info"
            )
            self.uvicorn_server = uvicorn.Server(config)
            self.uvicorn_server.run()
        except Exception as e:
            log_info(f"Server error: {str(e)}", TAG)

    def start_server(self):
        """Start the MCP server"""
        self.load_settings()
        if not self.server_thread or not self.server_thread.is_alive():
            self.server_thread = threading.Thread(target=self.run_server, daemon=False)
            self.server_thread.start()
            log_info(f"MCP Server started on {self.listen_host}:{self.listen_port}", TAG)

    def stop_server(self):
        """Stop the MCP server"""
        if self.uvicorn_server:
            self.uvicorn_server.should_exit = True
        if self.server_thread:
            self.server_thread.join()
        log_info("MCP Server stopped", TAG)

    def debug_bvs_status(self):
        """Check opened BinaryViews status"""
        for name, bv in list(self.bvs.items()):
            if not bv or bv.file.closed:
                log_debug(f"BinaryView closed: {name}", TAG)
                del self.bvs[name]

# Global plugin instance
plugin = MCPServerPlugin()

def plugin_init():
    # Register global handler for all BinaryView events
    BinaryViewType.add_binaryview_initial_analysis_completion_event(plugin.on_binaryview_initial_analysis_completion)

    PluginCommand.register(
        "MCPServer\\Start/Stop Server",
        "Start/Stop Server",
        plugin.server_control
    )

    PluginCommand.register(
        "MCPServer\\Debug Menu",
        "Check BinaryView Status",
        plugin.debug_bvs_status
    )
