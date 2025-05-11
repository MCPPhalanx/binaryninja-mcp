import os
import shutil
from pathlib import Path

import binaryninja as bn
import pytest

from binaryninja_mcp.utils import disable_binaryninja_user_plugins


def setup_binaryninja_user_config():
	"""
	Create an isolated BN user config with hardcoded settings.
	"""
	# copy license file to new user config directory.
	userconfigdir_current = Path(bn.user_directory())
	userconfigdir_isolated = Path(__file__).parent / 'bnuserconfig'

	license_file = userconfigdir_current / 'license.dat'
	if not userconfigdir_isolated.exists():
		userconfigdir_isolated.mkdir()
	if not license_file.exists():
		shutil.copy(license_file, userconfigdir_isolated)
	os.environ['BN_USER_DIRECTORY'] = str(userconfigdir_isolated)
	bn_settings = bn.Settings()

	# opinionated, set tab width to 3
	bn_settings.set_integer('rendering.hlil.tabWidth', 3)


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


disable_binaryninja_user_plugins()
setup_binaryninja_user_config()
