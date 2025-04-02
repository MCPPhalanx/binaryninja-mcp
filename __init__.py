from binaryninja_mcp.plugin import plugin_init
import binaryninja as bn

if bn.core_ui_enabled():
    plugin_init()
else:
    import warnings
    warnings.warn("BinaryNinja is running in Headless mode or accidentally sourced plugin file")
