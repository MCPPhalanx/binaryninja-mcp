import logging
import sys
try:
    from binaryninja.log import log_info, log_debug, log_warn, log_error, log_alert
except ImportError:
    import warnings
    warnings.warn("Install BinaryNinja API First")

BINJA_LOG_TAG = "MCPServer"

class BinjaLogHandler(logging.Handler):
    """Logging handler that routes messages to BinaryNinja's logging system"""


    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self.setFormatter(logging.Formatter('[%(name)s] %(message)s'))

    def emit(self, record):
        try:
            msg = self.format(record)
            if record.levelno >= logging.FATAL:
                log_alert(msg, BINJA_LOG_TAG)
            elif record.levelno >= logging.ERROR:
                log_error(msg, BINJA_LOG_TAG)
            elif record.levelno >= logging.WARNING:
                log_warn(msg, BINJA_LOG_TAG)
            elif record.levelno >= logging.INFO:
                log_info(msg, BINJA_LOG_TAG)
            elif record.levelno >= logging.DEBUG:
                log_debug(msg, BINJA_LOG_TAG)
        except Exception:
            self.handleError(record)

def setup_logging(log_level=logging.INFO, third_party_log_level=logging.WARNING):
    """Configure Python logging to use BinaryNinja's logging system

    Args:
        dev_mode (bool): If True, set log level to DEBUG
    """
    root = logging.getLogger()

    # Configure handlers
    binja_handler = BinjaLogHandler()
    stream_handler = logging.StreamHandler(sys.stderr)
    logging.basicConfig(level=third_party_log_level, handlers=[stream_handler, binja_handler])

    current_package = logging.getLogger("binaryninja_mcp")
    current_package.setLevel(log_level)

    return
