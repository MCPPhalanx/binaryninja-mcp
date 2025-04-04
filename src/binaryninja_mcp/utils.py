import os
import platform
from pathlib import Path, PurePath

try:
	import binaryninja as bn
except ImportError:
	import warnings

	warnings.warn('Install BinaryNinja API First')


def bv_name(bv: bn.BinaryView) -> str:
	return PurePath(bv.file.filename).name if bv.file else 'unnamed'


def disable_binaryninja_user_plugins():
	if (bn_already_init := getattr(bn, '_plugin_init')) is not None:
		assert bn_already_init is False, (
			'disable_binaryninja_user_plugins should be called before Binary Ninja initialization'
		)
	os.environ['BN_DISABLE_USER_PLUGINS'] = 'y'


def find_binaryninja_path(extra_path: str = None) -> Path | None:
	# If user provided path, check it first
	if extra_path:
		binja_paths = [Path(extra_path)]
	else:
		# Platform-specific default paths
		system = platform.system()
		if system == 'Windows':
			binja_paths = [
				Path('C:/Program Files/Vector35/BinaryNinja'),
				Path.home() / 'AppData/Local/Programs/Vector35/BinaryNinja',
				Path.home() / 'AppData/Local/Vector35/BinaryNinja',
			]
		elif system == 'Darwin':
			binja_paths = [
				Path('/Applications/Binary Ninja.app'),
				Path.home() / 'Applications/Binary Ninja.app',
			]
		else:  # Linux/other
			binja_paths = [Path('/opt/binaryninja'), Path.home() / 'binaryninja']

	# Look for install script in scripts directory
	for path in binja_paths:
		script_path = path / 'scripts/install_api.py'
		if script_path.exists():
			return path
