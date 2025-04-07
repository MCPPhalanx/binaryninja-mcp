import pytest
import binaryninja as bn
from binaryninja_mcp.utils import disable_binaryninja_user_plugins

disable_binaryninja_user_plugins()


@pytest.fixture(scope='function')
def bv():
	"""Fixture that loads the BNDB for beleaf.elf binary"""
	bv = bn.load('tests/binary/beleaf.elf.bndb')
	yield bv


@pytest.fixture(scope='function')
def bvs(bv):
	"""Fixture that loads the BNDB and ELF file for beleaf.elf binary"""
	bv2 = bn.load('tests/binary/beleaf.elf')
	yield [bv, bv2]
