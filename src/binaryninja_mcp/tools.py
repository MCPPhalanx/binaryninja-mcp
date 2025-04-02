from typing import Dict, List, Any, Optional, Tuple, Union
import binaryninja as bn
from mcp.types import TextContent, ImageContent, EmbeddedResource

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

            # Get decompiled code
            decompiled = func.hlil.decompile()
            if not decompiled:
                return [TextContent(
                    type="text",
                    text=f"Error: Failed to decompile function at {address}"
                )]

            return [TextContent(
                type="text",
                text=str(decompiled)
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

            # Check if Rust decompiler is available
            if not hasattr(func, "rust_decompile") and not hasattr(func.hlil, "rust_decompile"):
                return [TextContent(
                    type="text",
                    text="Error: Rust decompiler is not available in this version of Binary Ninja"
                )]

            # Try to decompile to Rust
            try:
                if hasattr(func, "rust_decompile"):
                    decompiled = func.rust_decompile()
                else:
                    decompiled = func.hlil.rust_decompile()

                if not decompiled:
                    return [TextContent(
                        type="text",
                        text=f"Error: Failed to decompile function at {address} to Rust"
                    )]

                return [TextContent(
                    type="text",
                    text=str(decompiled)
                )]
            except:
                # Fallback to C decompilation with a note
                decompiled = func.hlil.decompile()
                if not decompiled:
                    return [TextContent(
                        type="text",
                        text=f"Error: Failed to decompile function at {address}"
                    )]

                return [TextContent(
                    type="text",
                    text=f"// Note: Rust decompilation failed, showing C decompilation instead\n{str(decompiled)}"
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

            return [TextContent(
                type="text",
                text=str(hlil)
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

            return [TextContent(
                type="text",
                text=str(mlil)
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
                for i in range(0, length, 4):  # Assuming 4-byte instructions for simplicity
                    current_addr = addr + i
                    if current_addr >= self.bv.end:
                        break

                    # Get disassembly at this address
                    tokens = self.bv.get_disassembly(current_addr)
                    if tokens:
                        disasm.append(f"{hex(current_addr)}: {tokens}")

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

            # Get function disassembly
            disasm = []
            for block in func.basic_blocks:
                disasm.append(f"# Basic Block {hex(block.start)}")
                for addr in range(block.start, block.end):
                    tokens = self.bv.get_disassembly(addr)
                    if tokens:
                        disasm.append(f"{hex(addr)}: {tokens}")

            if not disasm:
                return [TextContent(
                    type="text",
                    text=f"Error: Failed to disassemble function at {address}"
                )]

            return [TextContent(
                type="text",
                text="\n".join(disasm)
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
