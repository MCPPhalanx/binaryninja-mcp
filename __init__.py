from binaryninja_mcp.plugin import plugin_init
import binaryninja as bn

# check if binaryninja plugin system is initialized
if bn.core_ui_enabled():
	plugin_init()
else:
	import warnings

	warnings.warn('BinaryNinja Plugin is accidentally loaded outside of BinaryNinja')
