import binaryninja as bn
import pytest

from binaryninja_mcp.utils import disable_binaryninja_user_plugins

disable_binaryninja_user_plugins()


@pytest.fixture
def bv():
	"""Fixture that loads the BNDB for beleaf.elf binary"""
	bv = bn.load('tests/binary/beleaf.elf.bndb')
	yield bv


@pytest.fixture
def bvs(bv):
	"""Fixture that loads the BNDB and ELF file for beleaf.elf binary"""
	bv2 = bn.load('tests/binary/beleaf.elf')
	yield [bv, bv2]
