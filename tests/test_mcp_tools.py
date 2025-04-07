import asyncio
import json
from typing import List

import pytest
import pytest_asyncio
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.types import TextContent

from binaryninja_mcp.server import create_mcp_server

# Address of main function in the test binary
ADDR_MAIN = '0x000008a1'

MCP_SERVER_HOST = 'localhost'


def textcontent_no_error(result: List[TextContent]) -> bool:
	"""Helper to verify no error messages in TextContent results"""
	for content in result:
		if 'Error: ' in content.text:
			return False
	return True


@pytest_asyncio.fixture
async def mcp_server(bvs, unused_tcp_port):
	server = create_mcp_server(bvs, host=MCP_SERVER_HOST, port=unused_tcp_port)
	task = asyncio.create_task(server.run_sse_async())
	try:
		yield (MCP_SERVER_HOST, unused_tcp_port)
	finally:
		task.cancel()


@pytest_asyncio.fixture
async def mcp_client(mcp_server):
	"""Fixture that provides an MCP client connected to the server"""
	host, port = mcp_server

	# Create server parameters
	async with sse_client(f'http://{host}:{port}/sse') as (read_stream, write_stream):
		async with ClientSession(read_stream, write_stream) as session:
			await session.initialize()
			yield session


@pytest.mark.asyncio
async def test_list_tools(mcp_client: ClientSession):
	"""Test listing available tools"""
	tools = await mcp_client.list_tools()

	# Verify that all expected tools are present
	expected_tools = [
		'list_filename',
		'get_triage_summary',
		'get_imports',
		'get_exports',
		'get_segments',
		'get_sections',
		'get_strings',
		'get_functions',
		'get_data_variables',
		'rename_symbol',
		'pseudo_c',
		'pseudo_rust',
		'high_level_il',
		'medium_level_il',
		'disassembly',
		'update_analysis_and_wait',
	]

	tool_names = [tool.name for tool in tools.tools]
	for expected_tool in expected_tools:
		assert expected_tool in tool_names, f'Tool {expected_tool} not found in available tools'


@pytest.mark.asyncio
async def test_list_filename(mcp_client):
	"""Test listing filenames"""
	result = await mcp_client.call_tool('list_filename')

	# Verify that the result contains at least one filename
	assert isinstance(result.content, list)
	assert len(result.content) == 2
	assert all(isinstance(c, TextContent) for c in result.content)

	assert result.content[0].text == 'beleaf.elf.bndb'
	assert result.content[1].text == 'beleaf.elf'


@pytest.mark.asyncio
async def test_get_triage_summary_valid(mcp_client, snapshot):
	"""Test getting triage summary with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	assert result == snapshot


@pytest.mark.asyncio
async def test_get_triage_summary_invalid(mcp_client):
	"""Test getting triage summary with invalid filename"""
	result = await mcp_client.call_tool('get_triage_summary', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_get_imports_valid(mcp_client):
	"""Test getting imports with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get imports
	result = await mcp_client.call_tool('get_imports', {'filename': filename})

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)

	# Parse the JSON result
	imports = json.loads(result.content[0].text)

	# Verify that the result is a dictionary
	assert isinstance(imports, dict)


@pytest.mark.asyncio
async def test_get_imports_invalid(mcp_client):
	"""Test getting imports with invalid filename"""
	result = await mcp_client.call_tool('get_imports', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_get_exports_valid(mcp_client):
	"""Test getting exports with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get exports
	result = await mcp_client.call_tool('get_exports', {'filename': filename})

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)

	# Parse the JSON result
	exports = json.loads(result.content[0].text)

	# Verify that the result is a list
	assert isinstance(exports, list)


@pytest.mark.asyncio
async def test_get_exports_invalid(mcp_client):
	"""Test getting exports with invalid filename"""
	result = await mcp_client.call_tool('get_exports', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_get_segments_valid(mcp_client):
	"""Test getting segments with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get segments
	result = await mcp_client.call_tool('get_segments', {'filename': filename})

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)

	# Parse the JSON result
	segments = json.loads(result.content[0].text)

	# Verify that the result is a list
	assert isinstance(segments, list)
	assert len(segments) > 0

	# Verify that each segment has the expected fields
	for segment in segments:
		assert 'start' in segment
		assert 'end' in segment
		assert 'length' in segment


@pytest.mark.asyncio
async def test_get_segments_invalid(mcp_client):
	"""Test getting segments with invalid filename"""
	result = await mcp_client.call_tool('get_segments', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_get_sections_valid(mcp_client):
	"""Test getting sections with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get sections
	result = await mcp_client.call_tool('get_sections', {'filename': filename})

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)

	# Parse the JSON result
	sections = json.loads(result.content[0].text)

	# Verify that the result is a list
	assert isinstance(sections, list)

	# Verify that each section has the expected fields
	for section in sections:
		assert 'name' in section
		assert 'start' in section
		assert 'end' in section
		assert 'length' in section


@pytest.mark.asyncio
async def test_get_sections_invalid(mcp_client):
	"""Test getting sections with invalid filename"""
	result = await mcp_client.call_tool('get_sections', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_get_strings_valid(mcp_client):
	"""Test getting strings with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get strings
	result = await mcp_client.call_tool('get_strings', {'filename': filename})

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)

	# Parse the JSON result
	strings = json.loads(result.content[0].text)

	# Verify that the result is a list
	assert isinstance(strings, list)

	# Verify that each string has the expected fields
	for string in strings:
		assert 'value' in string
		assert 'start' in string
		assert 'length' in string
		assert 'type' in string


@pytest.mark.asyncio
async def test_get_strings_invalid(mcp_client):
	"""Test getting strings with invalid filename"""
	result = await mcp_client.call_tool('get_strings', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_get_functions_valid(mcp_client):
	"""Test getting functions with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get functions
	result = await mcp_client.call_tool('get_functions', {'filename': filename})

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)

	# Parse the JSON result
	functions = json.loads(result.content[0].text)

	# Verify that the result is a list
	assert isinstance(functions, list)
	assert len(functions) > 0

	# Verify that each function has the expected fields
	for function in functions:
		assert 'name' in function
		assert 'start' in function


@pytest.mark.asyncio
async def test_get_functions_invalid(mcp_client):
	"""Test getting functions with invalid filename"""
	result = await mcp_client.call_tool('get_functions', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_get_data_variables_valid(mcp_client):
	"""Test getting data variables with valid filename"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get data variables
	result = await mcp_client.call_tool('get_data_variables', {'filename': filename})

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)

	# Parse the JSON result
	data_variables = json.loads(result.content[0].text)

	# Verify that the result is a list
	assert isinstance(data_variables, list)

	# Verify that each data variable has the expected fields
	for data_variable in data_variables:
		assert 'address' in data_variable


@pytest.mark.asyncio
async def test_get_data_variables_invalid(mcp_client):
	"""Test getting data variables with invalid filename"""
	result = await mcp_client.call_tool('get_data_variables', {'filename': 'invalid_filename'})

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_rename_symbol_valid(mcp_client):
	"""Test renaming a symbol with valid filename and address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Rename a symbol
	result = await mcp_client.call_tool(
		'rename_symbol',
		{'filename': filename, 'address_or_name': ADDR_MAIN, 'new_name': 'test_renamed_function'},
	)

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Successfully renamed' in result.content[0].text


@pytest.mark.asyncio
async def test_rename_symbol_invalid_filename(mcp_client):
	"""Test renaming a symbol with invalid filename"""
	result = await mcp_client.call_tool(
		'rename_symbol',
		{
			'filename': 'invalid_filename',
			'address_or_name': ADDR_MAIN,
			'new_name': 'test_renamed_function',
		},
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_rename_symbol_invalid_address(mcp_client):
	"""Test renaming a symbol with invalid address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Rename a symbol with invalid address
	result = await mcp_client.call_tool(
		'rename_symbol',
		{'filename': filename, 'address_or_name': '0xINVALID', 'new_name': 'test_renamed_function'},
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_pseudo_c_valid(mcp_client):
	"""Test getting pseudo C code with valid filename and address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get pseudo C code
	result = await mcp_client.call_tool(
		'pseudo_c', {'filename': filename, 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert len(result.content[0].text) > 0
	assert 'Error' not in result.content[0].text


@pytest.mark.asyncio
async def test_pseudo_c_invalid_filename(mcp_client):
	"""Test getting pseudo C code with invalid filename"""
	result = await mcp_client.call_tool(
		'pseudo_c', {'filename': 'invalid_filename', 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_pseudo_c_invalid_address(mcp_client):
	"""Test getting pseudo C code with invalid address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get pseudo C code with invalid address
	result = await mcp_client.call_tool(
		'pseudo_c', {'filename': filename, 'address_or_name': '0xINVALID'}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_pseudo_rust_valid(mcp_client):
	"""Test getting pseudo Rust code with valid filename and address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get pseudo Rust code
	result = await mcp_client.call_tool(
		'pseudo_rust', {'filename': filename, 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert len(result.content[0].text) > 0
	assert 'Error' not in result.content[0].text


@pytest.mark.asyncio
async def test_pseudo_rust_invalid_filename(mcp_client):
	"""Test getting pseudo Rust code with invalid filename"""
	result = await mcp_client.call_tool(
		'pseudo_rust', {'filename': 'invalid_filename', 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_pseudo_rust_invalid_address(mcp_client):
	"""Test getting pseudo Rust code with invalid address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get pseudo Rust code with invalid address
	result = await mcp_client.call_tool(
		'pseudo_rust', {'filename': filename, 'address_or_name': '0xINVALID'}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_high_level_il_valid(mcp_client):
	"""Test getting high level IL with valid filename and address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get high level IL
	result = await mcp_client.call_tool(
		'high_level_il', {'filename': filename, 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert len(result.content[0].text) > 0
	assert 'Error' not in result.content[0].text


@pytest.mark.asyncio
async def test_high_level_il_invalid_filename(mcp_client):
	"""Test getting high level IL with invalid filename"""
	result = await mcp_client.call_tool(
		'high_level_il', {'filename': 'invalid_filename', 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_high_level_il_invalid_address(mcp_client):
	"""Test getting high level IL with invalid address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get high level IL with invalid address
	result = await mcp_client.call_tool(
		'high_level_il', {'filename': filename, 'address_or_name': '0xINVALID'}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_medium_level_il_valid(mcp_client):
	"""Test getting medium level IL with valid filename and address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get medium level IL
	result = await mcp_client.call_tool(
		'medium_level_il', {'filename': filename, 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert len(result.content[0].text) > 0
	assert 'Error' not in result.content[0].text


@pytest.mark.asyncio
async def test_medium_level_il_invalid_filename(mcp_client):
	"""Test getting medium level IL with invalid filename"""
	result = await mcp_client.call_tool(
		'medium_level_il', {'filename': 'invalid_filename', 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_medium_level_il_invalid_address(mcp_client):
	"""Test getting medium level IL with invalid address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get medium level IL with invalid address
	result = await mcp_client.call_tool(
		'medium_level_il', {'filename': filename, 'address_or_name': '0xINVALID'}
	)

	# Verify that the result contains an error message
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert 'Error' in result.content[0].text


@pytest.mark.asyncio
async def test_disassembly_valid(mcp_client):
	"""Test getting disassembly with valid filename and address"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get disassembly
	result = await mcp_client.call_tool(
		'disassembly', {'filename': filename, 'address_or_name': ADDR_MAIN}
	)

	# Verify that the result is valid
	assert isinstance(result.content, list)
	assert len(result.content) > 0
	assert isinstance(result.content[0], TextContent)
	assert len(result.content[0].text) > 0
	assert 'Error' not in result.content[0].text


@pytest.mark.asyncio
async def test_disassembly_with_length(mcp_client):
	"""Test getting disassembly with valid filename, address, and length"""
	# First get the list of filenames
	result = await mcp_client.call_tool('list_filename')
	filenames = json.loads(result.content[0].text)

	# Use the first filename
	filename = filenames[0]

	# Get disassembly with length
	result = await mcp_client.call_tool(
		'disassembly', {'filename': filename, 'address_or_name': ADDR_MAIN, 'length': 16}
	)

	# Verify that the result is valid
	assert isinstance(result.content, list)
