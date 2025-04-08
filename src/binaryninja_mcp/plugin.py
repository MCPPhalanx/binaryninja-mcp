import logging
from typing import Dict, Optional

from binaryninja.binaryview import BinaryView, BinaryViewType
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings

from binaryninja_mcp.consts import DEFAULT_PORT
from binaryninja_mcp.log import setup_logging
from binaryninja_mcp.server import SSEServerThread, create_mcp_server
from binaryninja_mcp.utils import bv_name

logger = logging.getLogger(__name__)
SETTINGS_NAMESPACE = 'mcpserver'


class MCPServerPlugin:
	def __init__(self):
		self.bvs: Dict[str, BinaryView] = {}
		self.server_thread: Optional[SSEServerThread] = None
		self.settings = Settings()
		self.register_settings()
		self.load_settings()

	def register_settings(self):
		"""Register settings with default values"""
		self.settings.register_group(SETTINGS_NAMESPACE, 'MCP Server')
		self.settings.register_setting(
			f'{SETTINGS_NAMESPACE}.listen_host',
			'{"title":"Listen Host","description":"Server bind address","type":"string","default":"localhost"}',
		)
		self.settings.register_setting(
			f'{SETTINGS_NAMESPACE}.listen_port',
			f'{{"title":"Listen Port","description":"Server port number","type":"number","minValue":1,"maxValue":65535,"default":{DEFAULT_PORT}}}',
		)
		self.settings.register_setting(
			f'{SETTINGS_NAMESPACE}.auto_start',
			'{"title":"Auto Start","description":"Start MCP server when the first file is loaded","type":"boolean","default":true}',
		)

	def load_settings(self):
		"""Load settings from persistent storage"""
		self.listen_host = self.settings.get_string(f'{SETTINGS_NAMESPACE}.listen_host')
		self.listen_port = self.settings.get_integer(f'{SETTINGS_NAMESPACE}.listen_port')
		self.auto_start = self.settings.get_bool(f'{SETTINGS_NAMESPACE}.auto_start')

	def save_settings(self):
		"""Persist current settings"""
		self.settings.set_string(f'{SETTINGS_NAMESPACE}.listen_host', self.listen_host)
		self.settings.set_integer(f'{SETTINGS_NAMESPACE}.listen_port', self.listen_port)
		self.settings.set_bool(f'{SETTINGS_NAMESPACE}.listen_port', self.auto_start)

	def on_binaryview_initial_analysis_completion(self, bv: BinaryView):
		name = bv_name(bv)
		self.bvs[name] = bv
		logger.debug('Detected new BinaryView. bv=%s bv.file=%s name=%s', bv, bv.file, name)
		if self.auto_start and not self.server_running():
			# Auto-start server on plugin init
			self.start_server()

	def server_running(self) -> bool:
		status = bool(self.server_thread and self.server_thread.is_alive())
		logger.debug('server_running: %s', status)
		return status

	def start_server(self):
		"""Start the MCP server"""
		self.load_settings()
		if not self.server_running():
			mcp = create_mcp_server(list(self.bvs.values()))
			self.server_thread = SSEServerThread(mcp.sse_app(), self.listen_host, self.listen_port)
			self.server_thread.start()
			logger.info('MCP Server started on %s:%d', self.listen_host, self.listen_port)

	def stop_server(self):
		"""Stop the MCP server"""
		logger.debug('Stopping background thread')
		self.server_thread.stop()
		logger.info('MCP Server stopped')

	def menu_server_control(self, bv: BinaryView):
		if self.server_running():
			self.stop_server()
		else:
			self.start_server()

	def menu_debug_bvs_status(self, bv: BinaryView):
		"""Check opened BinaryViews status"""
		for name, bv in list(self.bvs.items()):
			logger.debug('name=%s, bv=%s', name, bv)
			logger.debug('bv.file.analysis_changed=%s', bv.file.analysis_changed)


# Global plugin instance
plugin = MCPServerPlugin()


def plugin_init():
	# Binary Ninja has log filter in GUI, always output debug logs
	setup_logging(logging.DEBUG, setup_for_plugin=True)
	# Register global handler for all BinaryView events
	BinaryViewType.add_binaryview_initial_analysis_completion_event(
		plugin.on_binaryview_initial_analysis_completion
	)

	PluginCommand.register(
		'MCPServer\\Start/Stop Server', 'Start/Stop Server', plugin.menu_server_control
	)

	PluginCommand.register(
		'MCPServer\\Debug Menu', 'Check BinaryView Status', plugin.menu_debug_bvs_status
	)
	logger.debug('Plugin is loaded!')
