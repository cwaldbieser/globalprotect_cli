import rich
from logzero import logger
import logging
from rich.console import Console

_console = Console(stderr=True)


def inspect(thing):
    if logger.getEffectiveLevel() == logging.DEBUG:
        rich.inspect(thing, console=_console)
