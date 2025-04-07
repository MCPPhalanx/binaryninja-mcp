from typing import List

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session as memory_session
from mcp.types import TextContent

from binaryninja_mcp.server import create_mcp_server

# Address of main function in the test binary
TEST_BINARY_NAME = 'beleaf.elf.bndb'
TEST_FUNC = 'main'
TEST_FUNC_ADDR = '0x000008a1'
TEST_FUNC_ADDR_INVALID = '0xINVALID'

MCP_SERVER_HOST = 'localhost'

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
	return 'trio'


def pytest_generate_tests(metafunc: pytest.Metafunc):
	if 'filename' in metafunc.fixturenames:
		metafunc.parametrize('filename', [TEST_BINARY_NAME])
	if 'function_name' in metafunc.fixturenames:
		metafunc.parametrize('function_name', [TEST_FUNC])
	if 'function_address' in metafunc.fixturenames:
		metafunc.parametrize('function_address', [TEST_FUNC_ADDR, TEST_FUNC_ADDR_INVALID])


def textcontent_no_error(result: List[TextContent]) -> bool:
	"""Helper to verify no error messages in TextContent results"""
	for content in result.content:
		if 'Error: ' in content.text:
			return False
	return True


@pytest.fixture
async def mcp_server(bvs):
	return create_mcp_server(bvs)


async def test_list_tools(mcp_server: FastMCP, snapshot):
	"""Test listing available tools"""
	async with memory_session(mcp_server._mcp_server) as client:
		tools = await client.list_tools()
		assert tools == snapshot


async def test_list_filename(mcp_server: FastMCP, snapshot):
	"""Test listing filenames"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('list_filename')
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_triage_summary(mcp_server: FastMCP, filename, snapshot):
	"""Test getting triage summary with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_triage_summary', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_imports(mcp_server: FastMCP, filename, snapshot):
	"""Test getting imports with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_imports', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_exports(mcp_server: FastMCP, filename, snapshot):
	"""Test getting exports with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_exports', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_segments(mcp_server: FastMCP, filename, snapshot):
	"""Test getting segments with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_segments', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_sections(mcp_server: FastMCP, filename, snapshot):
	"""Test getting sections with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_sections', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_strings(mcp_server: FastMCP, filename, snapshot):
	"""Test getting strings with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_strings', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_functions(mcp_server: FastMCP, filename, snapshot):
	"""Test getting functions with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_functions', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_get_data_variables(mcp_server: FastMCP, filename, snapshot):
	"""Test getting data variables with valid filename"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool('get_data_variables', {'filename': filename})
		assert textcontent_no_error(result)
		assert result == snapshot


async def test_rename_symbol(mcp_server: FastMCP, filename, function_address, snapshot):
	"""Test renaming a symbol with valid filename and address"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool(
			'rename_symbol',
			{
				'filename': filename,
				'address_or_name': function_address,
				'new_name': 'test_renamed_function',
			},
		)
		if function_address != TEST_FUNC_ADDR_INVALID:
			assert textcontent_no_error(result)
		assert result == snapshot


async def test_pseudo_c(mcp_server: FastMCP, filename, function_address, snapshot):
	"""Test getting pseudo C code with valid filename and address"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool(
			'pseudo_c', {'filename': filename, 'address_or_name': function_address}
		)
		if function_address != TEST_FUNC_ADDR_INVALID:
			assert textcontent_no_error(result)
		assert result == snapshot


async def test_pseudo_rust(mcp_server: FastMCP, filename, function_address, snapshot):
	"""Test getting pseudo Rust code with valid filename and address"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool(
			'pseudo_rust', {'filename': filename, 'address_or_name': function_address}
		)
		if function_address != TEST_FUNC_ADDR_INVALID:
			assert textcontent_no_error(result)
		assert result == snapshot


async def test_high_level_il(mcp_server: FastMCP, filename, function_address, snapshot):
	"""Test getting high level IL with valid filename and address"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool(
			'high_level_il', {'filename': filename, 'address_or_name': function_address}
		)
		if function_address != TEST_FUNC_ADDR_INVALID:
			assert textcontent_no_error(result)
		assert result == snapshot


async def test_medium_level_il(mcp_server: FastMCP, filename, function_address, snapshot):
	"""Test getting medium level IL with valid filename and address"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool(
			'medium_level_il', {'filename': filename, 'address_or_name': function_address}
		)
		if function_address != TEST_FUNC_ADDR_INVALID:
			assert textcontent_no_error(result)
		assert result == snapshot


async def test_disassembly(mcp_server: FastMCP, filename, function_address, snapshot):
	"""Test getting disassembly with valid filename and address"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool(
			'disassembly', {'filename': filename, 'address_or_name': function_address}
		)
		if function_address != TEST_FUNC_ADDR_INVALID:
			assert textcontent_no_error(result)
		assert result == snapshot


async def test_disassembly_with_length(mcp_server: FastMCP, filename, function_address, snapshot):
	"""Test getting disassembly with valid filename, address, and length"""
	async with memory_session(mcp_server._mcp_server) as client:
		result = await client.call_tool(
			'disassembly', {'filename': filename, 'address_or_name': function_address, 'length': 16}
		)
		if function_address != TEST_FUNC_ADDR_INVALID:
			assert textcontent_no_error(result)
		assert result == snapshot
