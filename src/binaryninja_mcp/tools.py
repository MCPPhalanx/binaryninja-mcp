import json
from typing import List, Optional
import binaryninja as bn
from binaryninja_mcp.resources import MCPResource
from mcp.types import TextContent

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

    def rename_symbol(self, address_or_name: str, new_name: str) -> List[TextContent]:
        """Rename a function or a data variable

        Args:
            address_or_name: Address (hex string) or name of the symbol
            new_name: New name for the symbol

        Returns:
            List containing a TextContent with the result
        """
        try:
            # Convert hex string to int
            addr = self.resolve_symbol(address_or_name)
            if addr is None:
                return [TextContent(
                    type="text",
                    text=f"Error: No function or data variable found with name/address '{address_or_name}'"
                )]

            # Check if address is a function
            func = self.bv.get_function_at(addr)
            if func:
                old_name = func.name
                func.name = new_name
                return [TextContent(
                    type="text",
                    text=f"Successfully renamed function at {hex(addr)} from '{old_name}' to '{new_name}'"
                )]

            # Check if address is a data variable
            if addr in self.bv.data_vars:
                var = self.bv.data_vars[addr]
                old_name = var.name if hasattr(var, "name") else "unnamed"

                # Create a symbol at this address with the new name
                self.bv.define_user_symbol(bn.Symbol(
                    bn.SymbolType.DataSymbol,
                    addr,
                    new_name
                ))

                return [TextContent(
                    type="text",
                    text=f"Successfully renamed data variable at {hex(addr)} from '{old_name}' to '{new_name}'"
                )]

            return [TextContent(
                type="text",
                text=f"Error: No function or data variable found with name/address '{address_or_name}'"
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address_or_name}'. Expected hex string (e.g., '0x1000') or symbol name"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def pseudo_c(self, address_or_name: str) -> List[TextContent]:
        """Get pseudo C code of a specified function

        Args:
            address_or_name: Address (hex string) or name of the function

        Returns:
            List containing a TextContent with the pseudo C code
        """
        try:
            addr = self.resolve_symbol(address_or_name)
            if addr is None:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found with name/address '{address_or_name}'"
                )]

            func = self.bv.get_function_at(addr)
            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {hex(addr)}"
                )]

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

            lines_of_code = ''.join(lines)

            return [TextContent(
                type="text",
                text=lines_of_code
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address_or_name}'. Expected hex string (e.g., '0x1000') or symbol name"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def pseudo_rust(self, address_or_name: str) -> List[TextContent]:
        """Get pseudo Rust code of a specified function

        Args:
            address_or_name: Address (hex string) or name of the function

        Returns:
            List containing a TextContent with the pseudo Rust code
        """
        try:
            addr = self.resolve_symbol(address_or_name)
            if addr is None:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found with name/address '{address_or_name}'"
                )]

            func = self.bv.get_function_at(addr)
            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {hex(addr)}"
                )]

            lines = []
            settings = bn.DisassemblySettings()
            settings.set_option(bn.DisassemblyOption.ShowAddress, False)
            settings.set_option(bn.DisassemblyOption.WaitForIL, True)
            obj = bn.LinearViewObject.language_representation(self.bv, settings, language="Pseudo Rust")
            cursor_end = bn.LinearViewCursor(obj)
            cursor_end.seek_to_address(func.highest_address)
            body = self.bv.get_next_linear_disassembly_lines(cursor_end)
            cursor_end.seek_to_address(func.highest_address)
            header = self.bv.get_previous_linear_disassembly_lines(cursor_end)

            for line in header:
                lines.append(f'{str(line)}\n')

            for line in body:
                lines.append(f'{str(line)}\n')

            lines_of_code = ''.join(lines)

            return [TextContent(
                type="text",
                text=lines_of_code
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address_or_name}'. Expected hex string (e.g., '0x1000') or symbol name"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def high_level_il(self, address_or_name: str) -> List[TextContent]:
        """Get high level IL of a specified function

        Args:
            address_or_name: Address (hex string) or name of the function

        Returns:
            List containing a TextContent with the HLIL
        """
        try:
            addr = self.resolve_symbol(address_or_name)
            if addr is None:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found with name/address '{address_or_name}'"
                )]

            func = self.bv.get_function_at(addr)
            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {hex(addr)}"
                )]

            # Get HLIL
            hlil = func.hlil
            if not hlil:
                return [TextContent(
                    type="text",
                    text=f"Error: Failed to get HLIL for function at {hex(addr)}"
                )]

            # Format the HLIL output
            lines = []
            for instruction in hlil.instructions:
                lines.append(f"{instruction.address:#x}: {instruction}\n")

            return [TextContent(
                type="text",
                text=''.join(lines)
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address_or_name}'. Expected hex string (e.g., '0x1000') or symbol name"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def medium_level_il(self, address_or_name: str) -> List[TextContent]:
        """Get medium level IL of a specified function

        Args:
            address_or_name: Address (hex string) or name of the function

        Returns:
            List containing a TextContent with the MLIL
        """
        try:
            addr = self.resolve_symbol(address_or_name)
            if addr is None:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found with name/address '{address_or_name}'"
                )]

            func = self.bv.get_function_at(addr)
            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {hex(addr)}"
                )]

            # Get MLIL
            mlil = func.mlil
            if not mlil:
                return [TextContent(
                    type="text",
                    text=f"Error: Failed to get MLIL for function at {hex(addr)}"
                )]

            # Format the MLIL output
            lines = []
            for instruction in mlil.instructions:
                lines.append(f"{instruction.address:#x}: {instruction}\n")

            return [TextContent(
                type="text",
                text=''.join(lines)
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address_or_name}'. Expected hex string (e.g., '0x1000') or symbol name"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def disassembly(self, address_or_name: str, length: Optional[int] = None) -> List[TextContent]:
        """Get disassembly of a function or specified range

        Args:
            address_or_name: Address (hex string) or name to start disassembly
            length: Optional length of bytes to disassemble

        Returns:
            List containing a TextContent with the disassembly
        """
        try:
            addr = self.resolve_symbol(address_or_name)
            if addr is None:
                return [TextContent(
                    type="text",
                    text=f"Error: No symbol found with name/address '{address_or_name}'"
                )]

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
                        disasm.append(f"{hex(current_addr)}: {tokens}")

                    current_addr += instr_length
                    remaining_length -= instr_length

                    if remaining_length <= 0:
                        break

                if not disasm:
                    return [TextContent(
                        type="text",
                        text=f"Error: Failed to disassemble at address {hex(addr)} with length {length}"
                    )]

                return [TextContent(
                    type="text",
                    text="\n".join(disasm)
                )]

            # Otherwise, try to get function disassembly
            func = self.bv.get_function_at(addr)
            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {hex(addr)}"
                )]

            # Get function disassembly using linear disassembly
            lines = []
            settings = bn.DisassemblySettings()
            settings.set_option(bn.DisassemblyOption.ShowAddress, True)
            obj = bn.LinearViewObject.disassembly(self.bv, settings)
            cursor = bn.LinearViewCursor(obj)
            cursor.seek_to_address(func.start)

            # Get all lines until we reach the end of the function
            while cursor.current_address < func.highest_address:
                line = self.bv.get_next_linear_disassembly_lines(cursor)
                if not line:
                    break
                for l in line:
                    lines.append(f"{str(l)}")

            if not lines:
                return [TextContent(
                    type="text",
                    text=f"Error: Failed to disassemble function at {hex(addr)}"
                )]

            return [TextContent(
                type="text",
                text="\n".join(lines)
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address_or_name}'. Expected hex string (e.g., '0x1000') or symbol name"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    # Resource access tools
    def get_triage_summary(self) -> List[TextContent]:
        """Get basic information as shown in BinaryNinja Triage view"""
        try:
            data = self.resource.triage_summary()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting triage summary: {str(e)}"
            )]

    def get_imports(self) -> List[TextContent]:
        """Get dictionary of imported symbols"""
        try:
            data = self.resource.imports()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting imports: {str(e)}"
            )]

    def get_exports(self) -> List[TextContent]:
        """Get dictionary of exported symbols"""
        try:
            data = self.resource.exports()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting exports: {str(e)}"
            )]

    def get_segments(self) -> List[TextContent]:
        """Get list of memory segments"""
        try:
            data = self.resource.segments()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting segments: {str(e)}"
            )]

    def get_sections(self) -> List[TextContent]:
        """Get list of binary sections"""
        try:
            data = self.resource.sections()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting sections: {str(e)}"
            )]

    def get_strings(self) -> List[TextContent]:
        """Get list of strings found in the binary"""
        try:
            data = self.resource.strings()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting strings: {str(e)}"
            )]

    def get_functions(self) -> List[TextContent]:
        """Get list of functions"""
        try:
            data = self.resource.functions()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting functions: {str(e)}"
            )]

    def get_data_variables(self) -> List[TextContent]:
        """Get list of data variables"""
        try:
            data = self.resource.data_variables()
            return [TextContent(
                type="text",
                text=json.dumps(data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error getting data variables: {str(e)}"
            )]

    def update_analysis_and_wait(self) -> List[TextContent]:
        """Update analysis for the binary and wait for it to complete

        Returns:
            List containing a TextContent with the result
        """
        try:
            # Start the analysis update
            self.bv.update_analysis_and_wait()

            return [TextContent(
                type="text",
                text=f"Analysis updated successfully for {self.bv.file.filename}"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error updating analysis: {str(e)}"
            )]
