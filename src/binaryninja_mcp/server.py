import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from threading import Event, Thread
from typing import AsyncIterator, Dict, List, Optional

import anyio
import binaryninja as bn
from anyio import to_thread
from hypercorn.config import Config
from hypercorn.trio import serve
from mcp.server.fastmcp import Context, FastMCP

from binaryninja_mcp.resources import MCPResource
from binaryninja_mcp.tools import MCPTools
from binaryninja_mcp.utils import bv_name

logger = logging.getLogger(__name__)


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
			name = f'{base_name}_{counter}'
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
		logger.debug('Looking up BinaryView: %s', name)
		bv = self.bvs.get(name)
		if not bv:
			logger.error('BinaryView not found: %s', name)
			raise KeyError(
				f'filename not found: {name}, currently opened: {" , ".join(self.bvs.keys())}'
			)
		return bv


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[BNContext]:
	"""Application lifecycle manager with initial BinaryViews"""
	context = BNContext()

	# Add initial BinaryViews from server configuration
	for bv in getattr(server, 'initial_bvs', []):
		context.add_bv(bv)

	try:
		yield context
	finally:
		logger.debug('Cleaning up BNContext')
		context.bvs.clear()


def create_mcp_server(initial_bvs: Optional[List[bn.BinaryView]] = None, **mcp_settings) -> FastMCP:
	"""Initialize MCP server with optional initial BinaryViews

	Args:
	    initial_bvs: Optional list of BinaryViews to initialize the server with

	Returns:
	    Configured MCP server instance
	"""
	mcp = FastMCP(
		name='BinaryNinja',
		version='1.0.0',
		description='MCP server for Binary Ninja analysis',
		lifespan=lifespan,
		**mcp_settings,
	)

	# Store initial BinaryViews for use in lifespan
	mcp.initial_bvs = initial_bvs or []

	# Resource handlers
	@mcp.resource('binaryninja://{filename}/triage_summary')
	def resource_get_triage_summary(filename: str) -> dict:
		"""Get basic information as shown in BinaryNinja Triage view"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.triage_summary()

	@mcp.resource('binaryninja://{filename}/imports')
	def resource_get_imports(filename: str) -> dict:
		"""Get dictionary of imported symbols or functions with properties"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.imports()

	@mcp.resource('binaryninja://{filename}/exports')
	def resource_get_exports(filename: str) -> dict:
		"""Get dictionary of exported symbols or functions with properties"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.exports()

	@mcp.resource('binaryninja://{filename}/segments')
	def resource_get_segments(filename: str) -> list:
		"""Get list of memory segments"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.segments()

	@mcp.resource('binaryninja://{filename}/sections')
	def resource_get_sections(filename: str) -> list:
		"""Get list of binary sections"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.sections()

	@mcp.resource('binaryninja://{filename}/strings')
	def resource_get_strings(filename: str) -> list:
		"""Get list of strings found in the binary"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.strings()

	@mcp.resource('binaryninja://{filename}/functions')
	def resource_get_functions(filename: str) -> list:
		"""Get list of functions"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.functions()

	@mcp.resource('binaryninja://{filename}/data_variables')
	def resource_get_data_variables(filename: str) -> list:
		"""Get list of data variables"""
		bnctx: BNContext = mcp.get_context().request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		resource = MCPResource(bv)
		return resource.data_variables()

	# Tool handlers
	@mcp.tool()
	def list_filename(ctx: Context) -> List[str]:
		"""List file names of all opened files"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		return list(bnctx.bvs.keys())

	@mcp.tool()
	def get_triage_summary(filename: str, ctx: Context) -> dict:
		"""Get basic information as shown in BinaryNinja Triage view"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_triage_summary()

	@mcp.tool()
	def get_imports(filename: str, ctx: Context) -> dict:
		"""Get dictionary of imported symbols"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_imports()

	@mcp.tool()
	def get_exports(filename: str, ctx: Context) -> dict:
		"""Get dictionary of exported symbols"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_exports()

	@mcp.tool()
	def get_segments(filename: str, ctx: Context) -> list:
		"""Get list of memory segments"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_segments()

	@mcp.tool()
	def get_sections(filename: str, ctx: Context) -> list:
		"""Get list of binary sections"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_sections()

	@mcp.tool()
	def get_strings(filename: str, ctx: Context) -> list:
		"""Get list of strings found in the binary"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_strings()

	@mcp.tool()
	def get_functions(filename: str, ctx: Context) -> list:
		"""Get list of functions"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_functions()

	@mcp.tool()
	def get_data_variables(filename: str, ctx: Context) -> list:
		"""Get list of data variables"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_data_variables()

	@mcp.tool()
	def rename_symbol(filename: str, address_or_name: str, new_name: str, ctx: Context) -> str:
		"""Rename a function or a data variable"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.rename_symbol(address_or_name, new_name)

	@mcp.tool()
	def pseudo_c(filename: str, address_or_name: str, ctx: Context) -> str:
		"""Get pseudo C code of a specified function"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.pseudo_c(address_or_name)

	@mcp.tool()
	def pseudo_rust(filename: str, address_or_name: str, ctx: Context) -> str:
		"""Get pseudo Rust code of a specified function"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.pseudo_rust(address_or_name)

	@mcp.tool()
	def high_level_il(filename: str, address_or_name: str, ctx: Context) -> str:
		"""Get high level IL of a specified function"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.high_level_il(address_or_name)

	@mcp.tool()
	def medium_level_il(filename: str, address_or_name: str, ctx: Context) -> str:
		"""Get medium level IL of a specified function"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.medium_level_il(address_or_name)

	@mcp.tool()
	def disassembly(
		filename: str, address_or_name: str, ctx: Context, length: Optional[int] = None
	) -> str:
		"""Get disassembly of a function or specified range"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.disassembly(address_or_name, length)

	@mcp.tool()
	def update_analysis_and_wait(filename: str, ctx: Context) -> str:
		"""Update analysis for the binary and wait for it to complete"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.update_analysis_and_wait()

	@mcp.tool()
	def get_data_dump(
		filename: str,
		address: str,
		ctx: Context,
		window_size: int = 128,
		human_readable: bool = True,
	) -> str:
		"""Return a hex/data listing around a given address"""
		bnctx: BNContext = ctx.request_context.lifespan_context
		bv = bnctx.get_bv(filename)
		tools = MCPTools(bv)
		return tools.get_data_dump(address, window_size, human_readable)

	return mcp


class SSEServerThread(Thread):
	def __init__(self, asgiapp, host, port):
		super().__init__(name='SSE Server Thread', daemon=True)
		self.app = asgiapp
		self.config = Config()
		self.config.bind = [f'{host}:{port}']

	def run(self):
		self.shutdown_signal = Event()
		return anyio.run(self.arun, backend='trio')

	def stop(self):
		self.shutdown_signal.set()

	# When running event loop from a thread, anyio.open_signal_receiver does not work
	# (it only works from main thread). We have to use our own way to send signals.
	# In order to send signal from a synchronous thread to an asynchronous task,
	# I choose to use anyio.to_thread helper with threading.Event to bridge between those two worlds.

	async def arun(self):
		return await serve(self.app, self.config, shutdown_trigger=self._shutdown_trigger)

	async def _shutdown_trigger(self):
		logger.debug('Start listening for shutdown event')
		await to_thread.run_sync(self.shutdown_signal.wait)
		logger.debug('Shutdown event triggered')
