from binaryninja import *
from binaryninja_mcp import do_nothing


PluginCommand.register("Useless Plugin", "Basically does nothing", do_nothing)
