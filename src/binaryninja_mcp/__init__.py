from binaryninja import *

def main() -> None:
    print("Hello from binaryninja-mcp!")

def do_nothing(bv: BinaryView):
	show_message_box("Do Nothing", "Congratulations! You have successfully done nothing.\n\n" +
					 "Pat yourself on the back.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
