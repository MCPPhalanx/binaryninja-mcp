import functools
import logging
from typing import Any, Optional

import binaryninja as bn

from binaryninja_mcp.resources import MCPResource

# Set up logger
logger = logging.getLogger('binaryninja_mcp.tools')


def handle_exceptions(func):
	"""Decorator to handle exceptions in tool methods

	Logs the error and re-raises the exception
	"""

	@functools.wraps(func)
	def wrapper(*args, **kwargs):
		try:
			return func(*args, **kwargs)
		except Exception as e:
			logger.error(f'Error in {func.__name__}: {str(e)}')
			raise

	return wrapper


class MCPTools:
	"""Tool handler for Binary Ninja MCP tools"""

	def __init__(self, bv: bn.BinaryView):
		"""Initialize with a Binary Ninja BinaryView"""
		self.bv = bv
		self.resource = MCPResource(bv)

	def resolve_symbol(self, address_or_name: str) -> Optional[int]:
		"""Resolve a symbol name or address to a numeric address

		Args:
		    address_or_name: Either a hex address string or symbol name

		Returns:
		    Numeric address if found, None otherwise
		"""
		try:
			return int(address_or_name, 16)
		except ValueError:
			# Search functions
			for func in self.bv.functions:
				if func.name == address_or_name:
					return func.start
			# Search data variables
			for addr, var in self.bv.data_vars.items():
				if var.name == address_or_name:
					return addr
			return None

	@handle_exceptions
	def rename_symbol(self, address_or_name: str, new_name: str) -> str:
		"""Rename a function or a data variable

		Args:
		    address_or_name: Address (hex string) or name of the symbol
		    new_name: New name for the symbol

		Returns:
		    Success message string
		"""
		# Convert hex string to int
		addr = self.resolve_symbol(address_or_name)
		if addr is None:
			raise ValueError(
				f"No function or data variable found with name/address '{address_or_name}'"
			)

		# Check if address is a function
		func = self.bv.get_function_at(addr)
		if func:
			old_name = func.name
			func.name = new_name
			return f"Successfully renamed function at {hex(addr)} from '{old_name}' to '{new_name}'"

		# Check if address is a data variable
		if addr in self.bv.data_vars:
			var = self.bv.data_vars[addr]
			old_name = var.name if hasattr(var, 'name') else 'unnamed'

			# Create a symbol at this address with the new name
			self.bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, addr, new_name))

			return f"Successfully renamed data variable at {hex(addr)} from '{old_name}' to '{new_name}'"

		raise ValueError(
			f"No function or data variable found with name/address '{address_or_name}'"
		)

	@handle_exceptions
	def pseudo_c(self, address_or_name: str) -> str:
		"""Get pseudo C code of a specified function

		Args:
		    address_or_name: Address (hex string) or name of the function

		Returns:
		    Pseudo C code as string
		"""
		addr = self.resolve_symbol(address_or_name)
		if addr is None:
			raise ValueError(f"No function found with name/address '{address_or_name}'")

		func = self.bv.get_function_at(addr)
		if not func:
			raise ValueError(f'No function found at address {hex(addr)}')

		lines = []
		settings = bn.DisassemblySettings()
		settings.set_option(bn.DisassemblyOption.ShowAddress, False)
		settings.set_option(bn.DisassemblyOption.WaitForIL, True)
		obj = bn.LinearViewObject.language_representation(self.bv, settings)
		cursor_end = bn.LinearViewCursor(obj)
		cursor_end.seek_to_address(func.highest_address)
		body = self.bv.get_next_linear_disassembly_lines(cursor_end)
		cursor_end.seek_to_address(func.highest_address)
		header = self.bv.get_previous_linear_disassembly_lines(cursor_end)

		for line in header:
			lines.append(f'{str(line)}\n')

		for line in body:
			lines.append(f'{str(line)}\n')

		return ''.join(lines)

	@handle_exceptions
	def pseudo_rust(self, address_or_name: str) -> str:
		"""Get pseudo Rust code of a specified function

		Args:
		    address_or_name: Address (hex string) or name of the function

		Returns:
		    Pseudo Rust code as string
		"""
		addr = self.resolve_symbol(address_or_name)
		if addr is None:
			raise ValueError(f"No function found with name/address '{address_or_name}'")

		func = self.bv.get_function_at(addr)
		if not func:
			raise ValueError(f'No function found at address {hex(addr)}')

		lines = []
		settings = bn.DisassemblySettings()
		settings.set_option(bn.DisassemblyOption.ShowAddress, False)
		settings.set_option(bn.DisassemblyOption.WaitForIL, True)
		obj = bn.LinearViewObject.language_representation(self.bv, settings, language='Pseudo Rust')
		cursor_end = bn.LinearViewCursor(obj)
		cursor_end.seek_to_address(func.highest_address)
		body = self.bv.get_next_linear_disassembly_lines(cursor_end)
		cursor_end.seek_to_address(func.highest_address)
		header = self.bv.get_previous_linear_disassembly_lines(cursor_end)

		for line in header:
			lines.append(f'{str(line)}\n')

		for line in body:
			lines.append(f'{str(line)}\n')

		return ''.join(lines)

	@handle_exceptions
	def high_level_il(self, address_or_name: str) -> str:
		"""Get high level IL of a specified function

		Args:
		    address_or_name: Address (hex string) or name of the function

		Returns:
		    HLIL as string
		"""
		addr = self.resolve_symbol(address_or_name)
		if addr is None:
			raise ValueError(f"No function found with name/address '{address_or_name}'")

		func = self.bv.get_function_at(addr)
		if not func:
			raise ValueError(f'No function found at address {hex(addr)}')

		# Get HLIL
		hlil = func.hlil
		if not hlil:
			raise ValueError(f'Failed to get HLIL for function at {hex(addr)}')

		# Format the HLIL output
		lines = []
		for instruction in hlil.instructions:
			lines.append(f'{instruction.address:#x}: {instruction}\n')

		return ''.join(lines)

	@handle_exceptions
	def medium_level_il(self, address_or_name: str) -> str:
		"""Get medium level IL of a specified function

		Args:
		    address_or_name: Address (hex string) or name of the function

		Returns:
		    MLIL as string
		"""
		addr = self.resolve_symbol(address_or_name)
		if addr is None:
			raise ValueError(f"No function found with name/address '{address_or_name}'")

		func = self.bv.get_function_at(addr)
		if not func:
			raise ValueError(f'No function found at address {hex(addr)}')

		# Get MLIL
		mlil = func.mlil
		if not mlil:
			raise ValueError(f'Failed to get MLIL for function at {hex(addr)}')

		# Format the MLIL output
		lines = []
		for instruction in mlil.instructions:
			lines.append(f'{instruction.address:#x}: {instruction}\n')

		return ''.join(lines)

	@handle_exceptions
	def disassembly(self, address_or_name: str, length: Optional[int] = None) -> str:
		"""Get disassembly of a function or specified range

		Args:
		    address_or_name: Address (hex string) or name to start disassembly
		    length: Optional length of bytes to disassemble

		Returns:
		    Disassembly as string
		"""
		addr = self.resolve_symbol(address_or_name)
		if addr is None:
			raise ValueError(f"No symbol found with name/address '{address_or_name}'")

		# If length is provided, disassemble that range
		if length is not None:
			disasm = []
			# Get instruction lengths instead of assuming 4-byte instructions
			current_addr = addr
			remaining_length = length

			while remaining_length > 0 and current_addr < self.bv.end:
				# Get instruction length at this address
				instr_length = self.bv.get_instruction_length(current_addr)
				if instr_length == 0:
					instr_length = 1  # Fallback to 1 byte if instruction length is unknown

				# Get disassembly at this address
				tokens = self.bv.get_disassembly(current_addr)
				if tokens:
					disasm.append(f'{hex(current_addr)}: {tokens}')

				current_addr += instr_length
				remaining_length -= instr_length

				if remaining_length <= 0:
					break

			if not disasm:
				raise ValueError(
					f'Failed to disassemble at address {hex(addr)} with length {length}'
				)

			return '\n'.join(disasm)

		# Otherwise, try to get function disassembly
		func = self.bv.get_function_at(addr)
		if not func:
			raise ValueError(f'No function found at address {hex(addr)}')

		# Get function disassembly using linear disassembly
		result_lines = []
		settings = bn.DisassemblySettings()
		settings.set_option(bn.DisassemblyOption.ShowAddress, True)

		# Use single_function_disassembly which is specifically for disassembling a single function
		obj = bn.LinearViewObject.single_function_disassembly(func, settings)
		cursor = bn.LinearViewCursor(obj)
		cursor.seek_to_begin()

		# Get all lines until we reach the end
		while not cursor.after_end:
			lines = self.bv.get_next_linear_disassembly_lines(cursor)
			if not lines:
				break
			for line in lines:
				result_lines.append(str(line))

		if not result_lines:
			raise ValueError(f'Failed to disassemble function at {hex(addr)}')

		return '\n'.join(result_lines)

	# Resource access tools
	@handle_exceptions
	def get_triage_summary(self) -> Any:
		"""Get basic information as shown in BinaryNinja Triage view"""
		return self.resource.triage_summary()

	@handle_exceptions
	def get_imports(self) -> dict:
		"""Get dictionary of imported symbols"""
		return self.resource.imports()

	@handle_exceptions
	def get_exports(self) -> dict:
		"""Get dictionary of exported symbols"""
		return self.resource.exports()

	@handle_exceptions
	def get_segments(self) -> list:
		"""Get list of memory segments"""
		return self.resource.segments()

	@handle_exceptions
	def get_sections(self) -> list:
		"""Get list of binary sections"""
		return self.resource.sections()

	@handle_exceptions
	def get_strings(self) -> list:
		"""Get list of strings found in the binary"""
		return self.resource.strings()

	@handle_exceptions
	def get_functions(self) -> list:
		"""Get list of functions"""
		return self.resource.functions()

	@handle_exceptions
	def get_data_variables(self) -> list:
		"""Get list of data variables"""
		return self.resource.data_variables()

	@handle_exceptions
	def update_analysis_and_wait(self) -> str:
		"""Update analysis for the binary and wait for it to complete

		Returns:
		    Success message string
		"""
		# Start the analysis update
		self.bv.update_analysis_and_wait()
		return f'Analysis updated successfully for {self.bv.file.filename}'
