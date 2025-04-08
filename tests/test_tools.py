import pytest

from binaryninja_mcp.tools import MCPTools

ADDR_MAIN = '0x000008a1'


def textcontent_no_error(result):
	"""Helper to verify no error messages in TextContent results"""
	for content in result:
		if 'Error: ' in content.text:
			return False
	return True


@pytest.fixture
def tools(bv):
	"""Fixture that provides an MCPTools instance"""
	return MCPTools(bv)


def test_rename_symbol_function(tools, snapshot):
	"""Test renaming a function symbol"""
	result = tools.rename_symbol(ADDR_MAIN, 'new_function_name')
	assert textcontent_no_error(result)
	assert result == snapshot


def test_rename_symbol_invalid_address(tools, snapshot):
	"""Test renaming with invalid address"""
	result = tools.rename_symbol('invalid_address', 'new_name')
	assert not textcontent_no_error(result)
	assert result == snapshot


def test_pseudo_c(tools, snapshot):
	"""Test getting pseudo C code for a function"""
	result = tools.pseudo_c(ADDR_MAIN)
	assert textcontent_no_error(result)
	assert result == snapshot


def test_pseudo_c_invalid_address(tools, snapshot):
	"""Test getting pseudo C with invalid address"""
	result = tools.pseudo_c('invalid_address')
	assert not textcontent_no_error(result)
	assert result == snapshot


def test_pseudo_rust(tools, snapshot):
	"""Test getting pseudo Rust code for a function"""
	result = tools.pseudo_rust(ADDR_MAIN)
	assert textcontent_no_error(result)
	assert result == snapshot


def test_high_level_il(tools, snapshot):
	"""Test getting HLIL for a function"""
	result = tools.high_level_il(ADDR_MAIN)
	assert textcontent_no_error(result)
	assert result == snapshot


def test_medium_level_il(tools, snapshot):
	"""Test getting MLIL for a function"""
	result = tools.medium_level_il(ADDR_MAIN)
	assert textcontent_no_error(result)
	assert result == snapshot


def test_disassembly_function(tools, snapshot):
	"""Test getting function disassembly"""
	result = tools.disassembly(ADDR_MAIN)
	assert textcontent_no_error(result)
	assert result == snapshot


def test_disassembly_range(tools, snapshot):
	"""Test getting disassembly for a range"""
	result = tools.disassembly(ADDR_MAIN, length=16)
	assert textcontent_no_error(result)
	assert result == snapshot


def test_update_analysis_and_wait(tools, snapshot):
	"""Test updating analysis"""
	result = tools.update_analysis_and_wait()
	assert textcontent_no_error(result)
	assert result == snapshot
