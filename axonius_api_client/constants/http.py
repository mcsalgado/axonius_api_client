# -*- coding: utf-8 -*-
"""Constants for :mod:`axonius_api_client.http`."""
import dataclasses
import re
from typing import List, Optional, Pattern

from ..data import BaseData
from ..parsers.url_parser import T_Url
from .api import TIMEOUT_CONNECT, TIMEOUT_RESPONSE
from .logs import (
    LOG_DATEFMT_CONSOLE,
    LOG_DATEFMT_FILE,
    LOG_FILE_MAX_FILES,
    LOG_FILE_MAX_MB,
    LOG_FILE_NAME,
    LOG_FILE_PATH,
    LOG_FMT_BRIEF,
    LOG_FMT_VERBOSE,
    LOG_LEVEL_API,
    LOG_LEVEL_CONSOLE,
    LOG_LEVEL_FILE,
    LOG_LEVEL_HTTP,
    LOG_LEVEL_PACKAGE,
)
from .typer import (
    T_CoerceBool,
    T_CoerceInt,
    T_CoerceIntFloat,
    T_CoerceReListy,
    T_Cookies,
    T_Headers,
    T_LogLevel,
    T_Pathy,
    T_Verify,
)

LOG_HIDE_MATCHES: str = "~key,~secret,~^auth,~password"
LOG_HIDE_URLS: str = "~login,~auth"


class AttrMaps:
    """Mapping of response/request attributes to their formatting strings."""

    wildcards: List[str] = ["*", "all"]
    join: str = "\n  "
    join_pre: str = join
    tmpl: str = "{k}: {v}"

    response_map: dict = {
        "url": "{response.url!r}",
        "size": "{response.size_human!r}",
        "size_request": "{response.request.size_human!r}",
        "method": "{response.request.method!r}",
        "status": "{response.status_code!r}",
        "reason": "{response.reason!r}",
        "elapsed": "'{response.elapsed}'",
        "headers": "{response.clean_headers!r}",
        "headers_request": "{response.request.clean_headers!r}",
        "cookies": "{response.clean_cookies!r}",
        "cookies_request": "{response.request.clean_cookies!r}",
        "args": "{response.send_args}",
    }

    request_map: dict = {
        "url": "{request.url!r}",
        "size": "{request.size_human!r}",
        "method": "{request.method!r}",
        "headers": "{request.clean_headers!r}",
        "cookies": "{request.clean_cookies!r}",
        "args": "{request.send_args}",
    }
    """Mapping of request attributes to log to their formatting strings."""
    request_attrs: List[str] = wildcards + list(request_map)
    response_attrs: List[str] = wildcards + list(response_map)
    log_request_attrs: str = "url,size"
    log_response_attrs: str = "url,size,status,elapsed"


@dataclasses.dataclass
class VarsHttp(BaseData):
    """Defaults for :meth:`axonius_api_client.http.Http.__init__`."""

    url: Optional[T_Url] = None
    certpath: Optional[T_Pathy] = None
    certverify: Optional[T_Verify] = False
    certwarn: Optional[T_CoerceBool] = True
    cert_client_both: Optional[T_Pathy] = None
    cert_client_cert: Optional[T_Pathy] = None
    cert_client_key: Optional[T_Pathy] = None
    headers: Optional[T_Headers] = None
    headers_auth: Optional[T_Headers] = None
    cookies: Optional[T_Cookies] = None
    proxy: Optional[str] = None
    proxy_http: Optional[str] = None
    proxy_https: Optional[str] = None
    timeout_connect: Optional[T_CoerceIntFloat] = TIMEOUT_CONNECT
    timeout_response: Optional[T_CoerceIntFloat] = TIMEOUT_RESPONSE
    user_agent: Optional[str] = None
    use_env_url: T_CoerceBool = True
    use_env_cookies: T_CoerceBool = True
    use_env_headers: T_CoerceBool = True
    use_env_user_agent: T_CoerceBool = True
    use_env_session: T_CoerceBool = True
    default_scheme: str = "https"
    save_history: T_CoerceBool = False
    log_body_lines: T_CoerceInt = 50
    log_level_http: Optional[T_LogLevel] = LOG_LEVEL_HTTP
    log_level_urllib: T_LogLevel = "warning"
    log_level_request_attrs: T_LogLevel = "debug"
    log_level_response_attrs: T_LogLevel = "debug"
    log_level_request_body: T_LogLevel = "debug"
    log_level_response_body: T_LogLevel = "debug"
    log_request_body: T_CoerceBool = False
    log_response_body: T_CoerceBool = False
    log_hide_str: str = "*********"
    log_hide_matches: Optional[T_CoerceReListy] = LOG_HIDE_MATCHES
    log_hide_urls: Optional[T_CoerceReListy] = LOG_HIDE_URLS
    log_request_attrs: Optional[List[str]] = AttrMaps.log_request_attrs
    log_response_attrs: Optional[List[str]] = AttrMaps.log_response_attrs


VARS_HTTP = VarsHttp()


@dataclasses.dataclass
class VarsClient(VarsHttp):
    """Defaults for :meth:`axonius_api_client.connect.Connect.__init__`."""

    eula_agreed: T_CoerceBool = False
    wraperror: T_CoerceBool = True
    log_console: T_CoerceBool = False
    log_console_fmt: str = LOG_FMT_BRIEF
    log_console_date_fmt: str = LOG_DATEFMT_CONSOLE
    log_file: T_CoerceBool = False
    log_file_fmt: str = LOG_FMT_VERBOSE
    log_file_date_fmt: str = LOG_DATEFMT_FILE
    log_file_max_files: Optional[T_CoerceInt] = LOG_FILE_MAX_FILES
    log_file_max_mb: Optional[T_CoerceInt] = LOG_FILE_MAX_MB
    log_file_name: T_Pathy = LOG_FILE_NAME
    log_file_path: T_Pathy = LOG_FILE_PATH
    log_file_rotate: T_CoerceBool = False
    log_level_api: T_LogLevel = LOG_LEVEL_API
    log_level_console: T_LogLevel = LOG_LEVEL_CONSOLE
    log_level_file: T_LogLevel = LOG_LEVEL_FILE
    log_level_package: T_LogLevel = LOG_LEVEL_PACKAGE
    use_env_creds: T_CoerceBool = True


VARS_CLIENT = VarsClient()


@dataclasses.dataclass
class VarsCli(BaseData):
    """Defaults for axonshell root group."""

    log_file_rotate: bool = True


VARS_CLI = VarsCli()


REASON_RES: List[Pattern] = [
    re.compile(r".*?object at.*?\>\: ([a-zA-Z0-9\]\[: ]+)", re.I),
    re.compile(r".*?\] (.*) ", re.I),
]
"""Patterns to look for in exceptions that we can pretty up for user display."""
