from typing import Any, Dict, List

import binaryninja as bn


class MCPResource:
	"""Resource handler for Binary Ninja MCP resources"""

	def __init__(self, bv: bn.BinaryView):
		"""Initialize with a Binary Ninja BinaryView"""
		self.bv = bv

	def triage_summary(self) -> Dict[str, Any]:
		"""Get basic information as shown in BinaryNinja Triage view"""
		result = {
			'file_metadata': {
				'filename': self.bv.file.filename,
				'file_size': self.bv.length,
				'view_type': self.bv.view_type,
			},
			'binary_info': {
				'platform': str(self.bv.platform),
				'entry_point': hex(self.bv.entry_point),
				'base_address': hex(self.bv.start),
				'end_address': hex(self.bv.end),
				'endianness': self.bv.endianness.name,
				'address_size': self.bv.address_size,
			},
			'statistics': {
				'function_count': len(list(self.bv.functions)),
				'string_count': len(list(self.bv.strings)),
				'segment_count': len(self.bv.segments),
				'section_count': len(self.bv.sections),
			},
		}

		# Add architecture info if available
		if hasattr(self.bv, 'arch') and self.bv.arch:
			result['binary_info']['architecture'] = self.bv.arch.name

		return result

	def imports(self) -> Dict[str, List[Dict[str, Any]]]:
		"""Get dictionary of imported symbols or functions with properties"""
		result: Dict[str, List[Dict[str, Any]]] = {}

		for sym in self.bv.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol):
			module = sym.namespace or 'unknown'
			if module not in result:
				result[module] = []

			result[module].append(
				{
					'name': sym.name,
					'address': hex(sym.address),
					'type': str(sym.type),
					'ordinal': sym.ordinal if hasattr(sym, 'ordinal') else None,
				}
			)

		for sym in self.bv.get_symbols_of_type(bn.SymbolType.ImportedDataSymbol):
			module = sym.namespace or 'unknown'
			if module not in result:
				result[module] = []

			result[module].append(
				{
					'name': sym.name,
					'address': hex(sym.address),
					'type': str(sym.type),
					'ordinal': sym.ordinal if hasattr(sym, 'ordinal') else None,
				}
			)

		return result

	def exports(self) -> List[Dict[str, Any]]:
		"""Get dictionary of exported symbols or functions with properties"""
		result = []

		for sym in self.bv.get_symbols_of_type(bn.SymbolType.FunctionSymbol):
			if sym.binding == bn.SymbolBinding.GlobalBinding:
				result.append(
					{
						'name': sym.name,
						'address': hex(sym.address),
						'type': str(sym.type),
						'ordinal': sym.ordinal if hasattr(sym, 'ordinal') else None,
					}
				)

		for sym in self.bv.get_symbols_of_type(bn.SymbolType.DataSymbol):
			if sym.binding == bn.SymbolBinding.GlobalBinding:
				result.append(
					{
						'name': sym.name,
						'address': hex(sym.address),
						'type': str(sym.type),
						'ordinal': sym.ordinal if hasattr(sym, 'ordinal') else None,
					}
				)

		return result

	def segments(self) -> List[Dict[str, Any]]:
		"""Get list of memory segments"""
		result = []

		for segment in self.bv.segments:
			result.append(
				{
					'start': hex(segment.start),
					'end': hex(segment.end),
					'length': segment.length,
					'data_offset': segment.data_offset,
					'data_length': segment.data_length,
					'data_end': segment.data_end,
					'readable': segment.readable,
					'writable': segment.writable,
					'executable': segment.executable,
				}
			)

		return result

	def sections(self) -> List[Dict[str, Any]]:
		"""Get list of binary sections"""
		result = []

		for section in self.bv.sections.values():
			result.append(
				{
					'name': section.name,
					'start': hex(section.start),
					'end': hex(section.end),
					'length': section.length,
					'type': section.type,
					'align': section.align,
					'entry_size': section.entry_size,
					'linked_section': section.linked_section,
					'info_section': section.info_section,
					'info_data': section.info_data,
				}
			)

		return result

	def strings(self) -> List[Dict[str, Any]]:
		"""Get list of strings found in the binary"""
		result = []

		for string in self.bv.strings:
			result.append(
				{
					'value': string.value,
					'start': hex(string.start),
					'length': string.length,
					'type': str(string.type),
				}
			)

		return result

	def functions(self) -> List[Dict[str, Any]]:
		"""Get list of functions"""
		result = []

		for function in self.bv.functions:
			result.append(
				{
					'name': function.name,
					'start': hex(function.start),
					'symbol': {
						'name': function.symbol.name,
						'type': str(function.symbol.type),
						'short_name': function.symbol.short_name,
					}
					if function.symbol
					else None,
					'parameter_count': len(function.parameter_vars),
					'return_type': str(function.return_type) if function.return_type else None,
					'has_prototype': function.has_user_type,
					'is_imported': function.symbol.type == bn.SymbolType.ImportedFunctionSymbol
					if function.symbol
					else False,
					'is_thunk': function.is_thunk,
					'basic_block_count': len(list(function.basic_blocks)),
				}
			)

		return result

	def data_variables(self) -> List[Dict[str, Any]]:
		"""Get list of data variables"""
		result = []

		for var_addr in self.bv.data_vars:
			var = self.bv.data_vars[var_addr]
			result.append(
				{
					'address': hex(var_addr),
					'type': str(var.type) if var.type else None,
					'auto_discovered': var.auto_discovered,
					'symbol': {
						'name': var.symbol.name,
						'type': str(var.symbol.type),
						'short_name': var.symbol.short_name,
					}
					if var.symbol
					else None,
				}
			)

		return result
