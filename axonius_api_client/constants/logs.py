# -*- coding: utf-8 -*-
"""Constants for logging."""
import logging
from typing import List

from .. import DEFAULT_PATH, PACKAGE_ROOT
from ..setup_env import DEBUG
from .typer import T_LogLevel

LOG_FMT_VERBOSE: str = (
    "%(asctime)s %(levelname)-8s [%(name)s:%(funcName)s:%(pathname)s:%(lineno)d] %(message)s"
)
"""Logging format to use for verbose logging."""

LOG_FMT_BRIEF: str = "%(levelname)-8s %(module)-15s %(message)s"
"""Logging format to use for brief logging."""

LOG_FMT_CONSOLE: str = LOG_FMT_VERBOSE if DEBUG else LOG_FMT_BRIEF
"""default logging format for console logs, will be verbose if package wide debugging is enabled"""

LOG_FMT_FILE: str = LOG_FMT_VERBOSE
"""default logging format for file logs"""

LOG_DATEFMT_CONSOLE: str = "%m/%d/%Y %I:%M:%S %p %Z"
"""default datetime format for console logs"""

LOG_DATEFMT_FILE: str = "%m/%d/%Y %I:%M:%S %p %Z"
"""default datetime format for file logs"""

LOG_LEVEL_CONSOLE: T_LogLevel = "debug"
"""default logging level for console log handlers"""

LOG_LEVEL_FILE: T_LogLevel = "debug"
"""default logging level for file log handlers"""

LOG_LEVEL_HTTP: T_LogLevel = "debug"
"""default logging level for :obj:`axonius_api_client.http.Http`"""

LOG_LEVEL_API: T_LogLevel = "debug"
"""default logging level for :obj:`axonius_api_client.api.mixins.ModelMixins`"""

LOG_LEVEL_AUTH: T_LogLevel = "debug"
"""default logging level for :obj:`axonius_api_client.auth.models.Model`"""

LOG_LEVEL_WIZARD: T_LogLevel = "debug"
"""default logging level for :obj:`axonius_api_client.api.wizards.wizard.Wizard`"""

LOG_LEVEL_PACKAGE: T_LogLevel = "debug"
"""default logging level for the entire package"""

LOG_LEVEL_PARSE: T_LogLevel = "debug"

LOG_LEVELS_STR: List[str] = ["debug", "info", "warning", "error", "fatal"]
"""list of valid logging level strs"""

LOG_LEVELS_STR_CSV: str = ", ".join(LOG_LEVELS_STR)
"""csv of valid logging level strs"""

LOG_LEVELS_INT: List[int] = [getattr(logging, x.upper()) for x in LOG_LEVELS_STR]
"""list of valid logging level ints"""

LOG_LEVELS_INT_CSV: str = ", ".join([str(x) for x in LOG_LEVELS_INT])
"""csv of valid logging level ints"""

LOG_FILE_PATH: str = DEFAULT_PATH
"""default path for log files"""

LOG_FILE_PATH_MODE = 0o700
""":obj:`oct` default permisisons to use when creating directories"""

LOG_FILE_NAME: str = f"{PACKAGE_ROOT}.log"
"""default log file name to use"""

LOG_FILE_MAX_MB: int = 5
"""default rollover trigger in MB"""

LOG_FILE_MAX_FILES: int = 5
"""default max rollovers to keep"""

LOG_NAME_STDERR: str = "handler_stderr"
"""default handler name for STDERR log"""

LOG_NAME_STDOUT: str = "handler_stdout"
"""default handler name for STDOUT log"""

LOG_NAME_FILE: str = "handler_file"
"""default handler name for file log"""
