from pathlib import PurePath
from binaryninja import BinaryView
from binaryninja.log import log_debug

def bv_name(bv: BinaryView) -> str:
    return PurePath(bv.file.filename).name if bv.file else "unnamed"
