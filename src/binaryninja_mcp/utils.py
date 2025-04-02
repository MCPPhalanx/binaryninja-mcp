import os
from pathlib import PurePath
from binaryninja import BinaryView

def bv_name(bv: BinaryView) -> str:
    return PurePath(bv.file.filename).name if bv.file else "unnamed"

def disable_binaryninja_user_plugins():
    os.environ["BN_DISABLE_USER_PLUGINS"] = "y"
