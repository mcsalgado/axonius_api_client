# -*- coding: utf-8 -*-
"""Logging utilities."""
import logging
import logging.handlers
import sys
import time
from typing import Dict, List, Optional, Union

from . import PACKAGE_LOG
from .constants.logs import (
    LOG_DATEFMT_CONSOLE,
    LOG_DATEFMT_FILE,
    LOG_FILE_MAX_FILES,
    LOG_FILE_MAX_MB,
    LOG_FILE_NAME,
    LOG_FILE_PATH,
    LOG_FILE_PATH_MODE,
    LOG_FMT_CONSOLE,
    LOG_FMT_FILE,
    LOG_LEVEL_CONSOLE,
    LOG_LEVEL_FILE,
    LOG_LEVEL_PACKAGE,
    LOG_LEVELS_INT_CSV,
    LOG_LEVELS_STR_CSV,
    LOG_NAME_FILE,
    LOG_NAME_STDERR,
    LOG_NAME_STDOUT,
)
from .constants.typer import T_LogLevel, T_LogObjs, T_Pathy
from .exceptions import ToolsError
from .tools import get_path, is_int


def gmtime():
    """Set the logging system to use GMT for time strings."""
    logging.Formatter.converter = time.gmtime


def localtime():
    """Set the logging system to use local time for time strings."""
    logging.Formatter.converter = time.localtime


def get_obj_log(
    obj: object,
    level: Optional[T_LogLevel] = None,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> logging.Logger:
    """Get a child logger for an object.

    Args:
        obj: object to get a logger for
        level: level to set
        logger: logger to get child from
    """
    log = get_obj_logger(obj=obj, logger=logger)
    set_log_level(obj=log, level=level)
    return log


def get_obj_logger(obj: object, logger: Optional[logging.Logger] = None) -> logging.Logger:
    """Get a child logger for an object.

    Args:
        obj: object to get a logger for
        level: level to set
        logger: logger to get child from
    """
    if not isinstance(logger, logging.Logger):
        logger = logging.getLogger(obj.__class__.__module__)
    log = logger.getChild(obj.__class__.__name__)
    return log


def set_log_level(obj: T_LogObjs, level: Optional[T_LogLevel] = None):
    """Set a logger or handler to a log level.

    Args:
        obj: object to set lvl on
        level: level to set
    """
    if isinstance(level, T_LogLevel):
        obj.setLevel(getattr(logging, str_level(level=level)))


def set_get_log_level(obj: Union[T_LogObjs, str], level: T_LogLevel, children: bool = False) -> str:
    """Set a logger or handler to a log level.

    Args:
        obj: object to set lvl on, if str, get logger
        level: level to set
    """
    if isinstance(obj, str):
        obj = logging.getLogger(obj)

    if not isinstance(obj, T_LogObjs):
        raise ToolsError(f"Obj {obj!r} must be {T_LogObjs}, not type {type(obj)}")

    level_str = str_level(level=level)
    level_int = getattr(logging, level_str)

    obj.setLevel(level_int)
    if children:
        for name, logger in obj.manager.loggerDict.items():
            if name.startswith(obj.name):
                obj.setLevel(level_int)
    return level_str


def str_level(level: T_LogLevel) -> str:
    """Get a logging level in str format.

    Args:
        level: level to get str format of

    Raises:
        :exc:`ToolsError`: if level is not mappable as an int or str to a known logger level
    """
    if is_int(obj=level, digit=True):
        level_mapped = logging.getLevelName(int(level))
        if hasattr(logging, level_mapped):
            return level_mapped

    if isinstance(level, str) and hasattr(logging, level.upper()):
        return level.upper()

    error = (
        f"Invalid logging level {level!r}, must be one of "
        f"{LOG_LEVELS_STR_CSV} or {LOG_LEVELS_INT_CSV}"
    )
    raise ToolsError(error)


def add_stderr(
    obj: logging.Logger,
    level: T_LogLevel = LOG_LEVEL_CONSOLE,
    hname: str = LOG_NAME_STDERR,
    fmt: str = LOG_FMT_CONSOLE,
    datefmt: str = LOG_DATEFMT_CONSOLE,
) -> logging.StreamHandler:
    """Add a StreamHandler to a logger object that outputs to STDERR.

    Args:
        obj: logger obj to add handler to
        level: log level to assign to handler
        hname: name to assign to handler
        fmt: logging format to use
        datefmt: date format to use
    """
    return add_handler(
        obj=obj,
        hname=hname,
        htype=logging.StreamHandler,
        level=level,
        fmt=fmt,
        datefmt=datefmt,
    )


def add_stdout(
    obj: logging.Logger,
    level: T_LogLevel = LOG_LEVEL_CONSOLE,
    hname: str = LOG_NAME_STDOUT,
    fmt: str = LOG_FMT_CONSOLE,
    datefmt: str = LOG_DATEFMT_CONSOLE,
) -> logging.StreamHandler:
    """Add a StreamHandler to a logger object that outputs to STDOUT.

    Args:
        obj: logger obj to add handler to
        level: log level to assign to handler
        hname: name to assign to handler
        fmt: logging format to use
        datefmt: date format to use
    """
    return add_handler(
        obj=obj,
        hname=hname,
        htype=logging.StreamHandler,
        level=level,
        fmt=fmt,
        datefmt=datefmt,
    )


def add_file(
    obj: logging.Logger,
    level: T_LogLevel = LOG_LEVEL_FILE,
    hname: str = LOG_NAME_FILE,
    file_path: T_Pathy = LOG_FILE_PATH,
    file_name: T_Pathy = LOG_FILE_NAME,
    file_path_mode=LOG_FILE_PATH_MODE,
    max_mb: Optional[int] = LOG_FILE_MAX_MB,
    max_files: Optional[int] = LOG_FILE_MAX_FILES,
    fmt: str = LOG_FMT_FILE,
    datefmt: str = LOG_DATEFMT_FILE,
) -> logging.handlers.RotatingFileHandler:
    """Add a RotatingFileHandler to a logger object.

    Args:
        obj: logger obj to add handler to
        level: log level to assign to handler
        hname: name to assign to handler
        fmt: logging format to use
        datefmt: date format to use
        file_path: path to write file_name to
        file_name: name of file to write log entries to
        file_path_mode: permissions to assign to directory for log file when created
        max_mb: rollover trigger in MB
        max_files: max files to keep for rollover
    """
    path = get_path(obj=file_path)
    path.mkdir(mode=file_path_mode, parents=True, exist_ok=True)

    args = {}
    if isinstance(max_mb, int) and max_mb > 0:
        args["maxBytes"] = max_mb * 1024 * 1024

    if isinstance(max_files, int) and max_files > 0:
        args["backupCount"] = max_files

    handler = add_handler(
        obj=obj,
        level=level,
        htype=logging.handlers.RotatingFileHandler,
        fmt=fmt,
        datefmt=datefmt,
        hname=hname,
        filename=str(path / file_name),
        **args,
    )
    handler.PATH = path
    return handler


def add_null(
    obj: logging.Logger, traverse: bool = True, hname="NULL"
) -> Optional[logging.NullHandler]:
    """Add a NullHandler to a logger if it has no handlers.

    Args:
        obj: logger obj to add handler to
        traverse: traverse the logger obj supplied up to the root logger
        hname: name to assign to handler
    """
    found = find_handlers(obj=obj, hname=hname, traverse=traverse)
    if found:
        return None
    return add_handler(obj=obj, htype=logging.NullHandler, hname=hname)


def add_handler(
    obj: logging.Logger,
    htype: logging.Handler,
    hname: str,
    fmt: str = LOG_FMT_CONSOLE,
    datefmt: str = LOG_DATEFMT_CONSOLE,
    level: Optional[T_LogLevel] = None,
    **kwargs,
) -> logging.Handler:
    """Add a handler to a logger obj.

    Args:
        obj: logger obj to add handler to
        htype: handler class to instantiate
        level: level to assign to handler obj
        hname: name to assign to handler obj
        fmt: logging format to assign to handler obj
        datefmt: date format to assign to handler obj
        **kwargs: passed to instantiation of htype
    """
    handler = htype(**kwargs)
    handler.name = hname
    set_log_level(obj=handler, level=level)
    handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    obj.addHandler(handler)
    return handler


def del_stderr(
    obj: logging.Logger, traverse: bool = True, hname: str = LOG_NAME_STDERR
) -> Dict[str, List[logging.Handler]]:
    """Remove the STDERR StreamHandler from a logger if found.

    Args:
        obj: logger obj to remove handler from
        traverse: traverse the logger obj supplied up to the root logger
        hname: name of handler to search for and remove
    """
    return del_handler(obj=obj, hname=hname, htype=logging.StreamHandler, traverse=traverse)


def del_stdout(
    obj: logging.Logger, traverse: bool = True, hname: str = LOG_NAME_STDOUT
) -> Dict[str, List[logging.Handler]]:
    """Remove the STDOUT StreamHandler from a logger if found.

    Args:
        obj: logger obj to remove handler from
        traverse: traverse the logger obj supplied up to the root logger
        hname: name of handler to search for and remove
    """
    return del_handler(obj=obj, hname=hname, htype=logging.StreamHandler, traverse=traverse)


def del_file(
    obj: logging.Logger, traverse: bool = True, hname=LOG_NAME_FILE
) -> Dict[str, List[logging.Handler]]:
    """Remove the RotatingFileHandler from a logger if found.

    Args:
        obj: logger obj to remove handler from
        traverse: traverse the logger obj supplied up to the root logger
        hname: name of handler to search for and remove
    """
    return del_handler(
        obj=obj,
        hname=hname,
        htype=logging.handlers.RotatingFileHandler,
        traverse=traverse,
    )


def del_null(
    obj: logging.Logger, traverse: bool = True, hname: str = "NULL"
) -> Dict[str, List[logging.Handler]]:
    """Remove the NullHandler from a logger if found.

    Args:
        obj: logger obj to remove handler from
        traverse: traverse the logger obj supplied up to the root logger
        hname: name of handler to search for and remove
    """
    return del_handler(obj=obj, hname=hname, htype=logging.NullHandler, traverse=traverse)


def del_handler(
    obj: logging.Logger,
    hname: str = "",
    htype: logging.Handler = None,
    traverse: bool = True,
) -> Dict[str, List[logging.Handler]]:
    """Remove the NullHandler from a logger if found.

    Args:
        obj: logger obj to remove handler from
        traverse: traverse the logger obj supplied up to the root logger
        hname: name of handler to search for and remove
        htype: type of handler to find and remove
    """
    found = find_handlers(obj=obj, hname=hname, htype=htype, traverse=traverse)
    for name, handlers in found.items():
        for handler in handlers:
            logging.getLogger(name).removeHandler(handler)
    return found


def find_handlers(
    obj: logging.Logger,
    hname: str = "",
    htype: logging.Handler = None,
    traverse: bool = True,
) -> Dict[str, List[logging.Handler]]:
    """Remove the NullHandler from a logger if found.

    Notes:
        * will remove handler if hname supplied and handler obj name matches
        * will remove handler if htype supplied and handler obj type matches

    Args:
        obj: logger obj to search for handler in
        traverse: traverse the logger obj supplied up to the root logger
        hname: name of handler to search for
        htype: type of handler to find
    """
    handlers = {}

    for handler in obj.handlers:
        match_name = hname and handler.name == hname
        match_type = htype and isinstance(handler, htype)

        if match_name or match_type:
            handlers[obj.name] = handlers.get(obj.name, [])

            if handler not in handlers[obj.name]:  # pragma: no cover
                handlers[obj.name].append(handler)

    if obj.parent and traverse:
        found = find_handlers(obj=obj.parent, hname=hname, htype=htype, traverse=traverse)
        handlers.update(found)

    return handlers


add_null(obj=PACKAGE_LOG)
gmtime()
set_log_level(obj=PACKAGE_LOG, level=LOG_LEVEL_PACKAGE)


def handle_unhandled_exception(exc_type, exc_value, exc_traceback):  # pragma: no cover
    """Log unhandled exceptions."""
    sys.__excepthook__(exc_type, exc_value, exc_traceback)
    PACKAGE_LOG.critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = handle_unhandled_exception
