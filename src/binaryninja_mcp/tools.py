from typing import List, Optional
import binaryninja as bn
from mcp.types import TextContent

class MCPTools:
    """Tool handler for Binary Ninja MCP tools"""

    def __init__(self, bv: bn.BinaryView):
        """Initialize with a Binary Ninja BinaryView"""
        self.bv = bv

    def rename_symbol(self, address: str, new_name: str) -> List[TextContent]:
        """Rename a function or a data variable

        Args:
            address: Address of the function or data variable (hex string)
            new_name: New name for the symbol

        Returns:
            List containing a TextContent with the result
        """
        try:
            # Convert hex string to int
            addr = int(address, 16)

            # Check if address is a function
            func = self.bv.get_function_at(addr)
            if func:
                old_name = func.name
                func.name = new_name
                return [TextContent(
                    type="text",
                    text=f"Successfully renamed function at {address} from '{old_name}' to '{new_name}'"
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
                    text=f"Successfully renamed data variable at {address} from '{old_name}' to '{new_name}'"
                )]

            return [TextContent(
                type="text",
                text=f"Error: No function or data variable found at address {address}"
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address}'. Expected hex string (e.g., '0x1000')"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def pseudo_c(self, address: str) -> List[TextContent]:
        """Get pseudo C code of a specified function

        Args:
            address: Address of the function (hex string)

        Returns:
            List containing a TextContent with the pseudo C code
        """
        try:
            addr = int(address, 16)
            func = self.bv.get_function_at(addr)

            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {address}"
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
                text=f"Error: Invalid address format '{address}'. Expected hex string (e.g., '0x1000')"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def pseudo_rust(self, address: str) -> List[TextContent]:
        """Get pseudo Rust code of a specified function

        Args:
            address: Address of the function (hex string)

        Returns:
            List containing a TextContent with the pseudo Rust code
        """
        try:
            addr = int(address, 16)
            func = self.bv.get_function_at(addr)

            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {address}"
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
                text=f"Error: Invalid address format '{address}'. Expected hex string (e.g., '0x1000')"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def high_level_il(self, address: str) -> List[TextContent]:
        """Get high level IL of a specified function

        Args:
            address: Address of the function (hex string)

        Returns:
            List containing a TextContent with the HLIL
        """
        try:
            addr = int(address, 16)
            func = self.bv.get_function_at(addr)

            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {address}"
                )]

            # Get HLIL
            hlil = func.hlil
            if not hlil:
                return [TextContent(
                    type="text",
                    text=f"Error: Failed to get HLIL for function at {address}"
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
                text=f"Error: Invalid address format '{address}'. Expected hex string (e.g., '0x1000')"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def medium_level_il(self, address: str) -> List[TextContent]:
        """Get medium level IL of a specified function

        Args:
            address: Address of the function (hex string)

        Returns:
            List containing a TextContent with the MLIL
        """
        try:
            addr = int(address, 16)
            func = self.bv.get_function_at(addr)

            if not func:
                return [TextContent(
                    type="text",
                    text=f"Error: No function found at address {address}"
                )]

            # Get MLIL
            mlil = func.mlil
            if not mlil:
                return [TextContent(
                    type="text",
                    text=f"Error: Failed to get MLIL for function at {address}"
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
                text=f"Error: Invalid address format '{address}'. Expected hex string (e.g., '0x1000')"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    def disassembly(self, address: str, length: Optional[int] = None) -> List[TextContent]:
        """Get disassembly of a function or specified range

        Args:
            address: Address to start disassembly (hex string)
            length: Optional length of bytes to disassemble

        Returns:
            List containing a TextContent with the disassembly
        """
        try:
            addr = int(address, 16)

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
                        text=f"Error: Failed to disassemble at address {address} with length {length}"
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
                    text=f"Error: No function found at address {address}"
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
                    text=f"Error: Failed to disassemble function at {address}"
                )]

            return [TextContent(
                type="text",
                text="\n".join(lines)
            )]
        except ValueError:
            return [TextContent(
                type="text",
                text=f"Error: Invalid address format '{address}'. Expected hex string (e.g., '0x1000')"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
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
