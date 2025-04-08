import pytest

from binaryninja_mcp.tools import MCPTools

ADDR_MAIN = '0x000008a1'


@pytest.fixture
def tools(bv):
	"""Fixture that provides an MCPTools instance"""
	return MCPTools(bv)


def test_rename_symbol_function(tools, snapshot):
	"""Test renaming a function symbol"""
	result = tools.rename_symbol(ADDR_MAIN, 'new_function_name')
	assert isinstance(result, str)
	assert result == snapshot


def test_rename_symbol_invalid_address(tools):
	"""Test renaming with invalid address"""
	with pytest.raises(ValueError) as excinfo:
		tools.rename_symbol('invalid_address', 'new_name')
	assert 'No function or data variable found' in str(excinfo.value)


def test_pseudo_c(tools, snapshot):
	"""Test getting pseudo C code for a function"""
	result = tools.pseudo_c(ADDR_MAIN)
	assert isinstance(result, str)
	assert result == snapshot


def test_pseudo_c_invalid_address(tools):
	"""Test getting pseudo C with invalid address"""
	with pytest.raises(ValueError) as excinfo:
		tools.pseudo_c('invalid_address')
	assert 'No function found' in str(excinfo.value)


def test_pseudo_rust(tools, snapshot):
	"""Test getting pseudo Rust code for a function"""
	result = tools.pseudo_rust(ADDR_MAIN)
	assert isinstance(result, str)
	assert result == snapshot


def test_high_level_il(tools, snapshot):
	"""Test getting HLIL for a function"""
	result = tools.high_level_il(ADDR_MAIN)
	assert isinstance(result, str)
	assert result == snapshot


def test_medium_level_il(tools, snapshot):
	"""Test getting MLIL for a function"""
	result = tools.medium_level_il(ADDR_MAIN)
	assert isinstance(result, str)
	assert result == snapshot


def test_disassembly_function(tools, snapshot):
	"""Test getting function disassembly"""
	result = tools.disassembly(ADDR_MAIN)
	assert isinstance(result, str)
	assert result == snapshot


def test_disassembly_range(tools, snapshot):
	"""Test getting disassembly for a range"""
	result = tools.disassembly(ADDR_MAIN, length=16)
	assert isinstance(result, str)
	assert result == snapshot


def test_update_analysis_and_wait(tools, snapshot):
	"""Test updating analysis"""
	result = tools.update_analysis_and_wait()
	assert isinstance(result, str)
	assert result == snapshot


def test_get_triage_summary(tools, snapshot):
	"""Test getting triage summary"""
	result = tools.get_triage_summary()
	assert isinstance(result, dict)
	assert result == snapshot


def test_get_imports(tools, snapshot):
	"""Test getting imports"""
	result = tools.get_imports()
	assert isinstance(result, dict)
	assert result == snapshot


def test_get_exports(tools, snapshot):
	"""Test getting exports"""
	result = tools.get_exports()
	assert isinstance(result, list)
	assert result == snapshot


def test_get_segments(tools, snapshot):
	"""Test getting segments"""
	result = tools.get_segments()
	assert isinstance(result, list)
	assert result == snapshot


def test_get_sections(tools, snapshot):
	"""Test getting sections"""
	result = tools.get_sections()
	assert isinstance(result, list)
	assert result == snapshot


def test_get_strings(tools, snapshot):
	"""Test getting strings"""
	result = tools.get_strings()
	assert isinstance(result, list)
	assert result == snapshot


def test_get_functions(tools, snapshot):
	"""Test getting functions"""
	result = tools.get_functions()
	assert isinstance(result, list)
	assert result == snapshot


def test_get_data_variables(tools, snapshot):
	"""Test getting data variables"""
	result = tools.get_data_variables()
	assert isinstance(result, list)
	assert result == snapshot
