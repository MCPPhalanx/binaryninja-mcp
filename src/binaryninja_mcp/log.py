import logging
import sys

try:
	from binaryninja.log import Logger as BNLogger
except ImportError:
	import warnings

	warnings.warn('Install BinaryNinja API First')

BINJA_LOG_TAG = 'MCPServer'


class BinjaLogHandler(logging.Handler):
	"""Logging handler that routes messages to BinaryNinja's logging system"""

	def __init__(self, level=logging.NOTSET):
		super().__init__(level)
		self.setFormatter(logging.Formatter('[%(name)s] %(message)s'))
		self.logger = BNLogger(0, BINJA_LOG_TAG)

	def emit(self, record):
		try:
			msg = self.format(record)
			if record.levelno >= logging.FATAL:
				self.logger.log_alert(msg)
			elif record.levelno >= logging.ERROR:
				self.logger.log_error(msg)
			elif record.levelno >= logging.WARNING:
				self.logger.log_warn(msg)
			elif record.levelno >= logging.INFO:
				self.logger.log_info(msg)
			elif record.levelno >= logging.DEBUG:
				self.logger.log_debug(msg)
		except Exception:
			self.handleError(record)


def setup_logging(log_level=logging.INFO, third_party_log_level=logging.WARNING):
	"""Configure Python logging to use BinaryNinja's logging system

	Args:
	    dev_mode (bool): If True, set log level to DEBUG
	"""
	# Configure handlers
	binja_handler = BinjaLogHandler()
	stream_handler = logging.StreamHandler(sys.stderr)
	logging.basicConfig(level=third_party_log_level, handlers=[stream_handler, binja_handler])

	current_package = logging.getLogger('binaryninja_mcp')
	current_package.setLevel(log_level)
