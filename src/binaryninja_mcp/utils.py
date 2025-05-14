import os
import platform
from pathlib import Path, PurePath

try:
	import binaryninja as bn
except ImportError:
	import warnings

	warnings.warn('Install BinaryNinja API First')


def bv_name(bv: 'bn.BinaryView') -> str:
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
				Path('/Applications/Binary Ninja.app/Contents/Resources'),
				Path.home() / 'Applications/Binary Ninja.app/Contents/Resources',
			]
		else:  # Linux/other
			binja_paths = [Path('/opt/binaryninja'), Path.home() / 'binaryninja']

	# Look for install script in scripts directory
	for path in binja_paths:
		script_path = path / 'scripts/install_api.py'
		if script_path.exists():
			return path


def hex_to_human(data: bytes, base_address: int = 0) -> str:
	"""Convert binary data to human-readable format like in hex viewers (hex + ascii)

	Args:
		data: Binary data to convert
		base_address: Base address for the data

	Returns:
		Human-readable hex string
	"""

	offset = base_address
	hex_lines = []
	# add formatted header: byte number and ascii section
	hex_lines.append('Address       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII')

	while data:
		# Format the address
		address_str = f'{offset:08x}     '
		chunk = data[:16]

		# Format the hex part
		hex_str = ' '.join(f'{byte:02x}' for byte in chunk)
		hex_str += '   '
		# Format the ASCII part
		ascii_str = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in chunk)
		# Pad the hex string to 48 characters
		hex_str = hex_str.ljust(48)
		# Combine address, hex, and ASCII parts
		hex_lines.append(f'{address_str}{hex_str}{ascii_str}')
		# Move to the next chunk
		data = data[16:]
		offset += 16
	return '\n'.join(hex_lines)
