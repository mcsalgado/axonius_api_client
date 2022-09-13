# -*- coding: utf-8 -*-
"""Easy all-in-one connection handler."""
import logging
import pathlib
from typing import List, Optional, Type

import requests

from . import PACKAGE_LOG
from .api import (
    ActivityLogs,
    Adapters,
    Dashboard,
    DataScopes,
    Devices,
    Enforcements,
    Instances,
    Meta,
    OpenAPISpec,
    RemoteSupport,
    SettingsGlobal,
    SettingsGui,
    SettingsIdentityProviders,
    SettingsLifecycle,
    Signup,
    SystemRoles,
    SystemUsers,
    Users,
    Vulnerabilities,
)
from .api.mixins import Model as ApiModel
from .cert_human.paths import pathify
from .constants.http import REASON_RES, VARS_CLIENT, VARS_HTTP
from .constants.typer import (
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
from .exceptions import ClientError, ConnectError, InvalidCredentials
from .http import Http, T_Url
from .logs import (
    add_file,
    add_stderr,
    del_file,
    del_stderr,
    set_get_log_level,
    set_log_level,
    str_level,
)
from .setup_env import get_env_values_client
from .tools import coerce_bool, coerce_int, is_str, json_dump, json_reload, sysinfo
from .version import __version__ as VERSION

CREDS: List[str] = ["key", "secret", "username", "password"]


class Client(Http):
    """Easy all-in-one connection handler for using the API client.

    Examples:
        >>> #!/usr/bin/env python
        >>> # -*- coding: utf-8 -*-
        >>> '''Base example for setting up the API client.'''
        >>> import axonius_api_client as axonapi
        >>>
        >>> # get the URL, API key, API secret, & certwarn from the default ".env" file
        >>> client_args = axonapi.get_env_client()
        >>>
        >>> # OR override OS env vars with the values from a custom .env file
        >>> # client_args = axonapi.get_env_client(ax_env="/path/to/envfile", override=True)
        >>>
        >>> # create a client using the url, key, and secret from OS env
        >>> client = axonapi.Client(**client_args)
        >>>
        >>> j = client.jdump  # json dump helper
        >>>
        >>> client.start()                  # connect to axonius
        >>>
        >>> # client.activity_logs          # get audit logs
        >>> # client.adapters               # get adapters and update adapter settings
        >>> # client.adapters.cnx           # CRUD for adapter connections
        >>> # client.dashboard              # get/start/stop discovery cycles
        >>> # client.devices                # get device assets
        >>> # client.devices.fields         # get field schemas for device assets
        >>> # client.devices.labels         # add/remove/get tags for device assets
        >>> # client.devices.saved_queries  # CRUD for saved queries for device assets
        >>> # client.enforcements           # CRUD for enforcements
        >>> # client.instances              # get instances and instance meta data
        >>> # client.meta                   # get product meta data
        >>> # client.remote_support         # enable/disable remote support settings
        >>> # client.settings_global        # get/update global system settings
        >>> # client.settings_gui           # get/update gui system settings
        >>> # client.settings_ip            # get/update identity provider system settings
        >>> # client.settings_lifecycle     # get/update lifecycle system settings
        >>> # client.signup                 # perform initial signup and use password reset tokens
        >>> # client.system_roles           # CRUD for system roles
        >>> # client.system_users           # CRUD for system users
        >>> # client.users                  # get user assets
        >>> # client.users.fields           # get field schemas for user assets
        >>> # client.users.labels           # add/remove/get tags for user assets
        >>> # client.users.saved_queries    # CRUD for saved queries for user assets

    """

    # XXX add Client(use_env_url=True, use_env_creds=True)

    VARS = VARS_CLIENT

    HANDLER_FILE: Optional[logging.handlers.RotatingFileHandler] = None
    """file logging handler"""

    HANDLER_CON: Optional[logging.StreamHandler] = None
    """console logging handler"""

    def __init__(
        self,
        url: Optional[T_Url] = VARS_CLIENT.url,
        key: Optional[str] = None,
        secret: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        eula_agreed: T_CoerceBool = VARS_CLIENT.eula_agreed,
        proxy: Optional[str] = VARS_CLIENT.proxy,
        wraperror: T_CoerceBool = VARS_CLIENT.wraperror,
        log_console: T_CoerceBool = VARS_CLIENT.log_console,
        log_console_date_fmt: str = VARS_CLIENT.log_console_date_fmt,
        log_console_fmt: str = VARS_CLIENT.log_console_fmt,
        log_file: T_CoerceBool = VARS_CLIENT.log_file,
        log_file_date_fmt: str = VARS_CLIENT.log_file_date_fmt,
        log_file_fmt: str = VARS_CLIENT.log_file_fmt,
        log_file_max_files: Optional[T_CoerceInt] = VARS_CLIENT.log_file_max_files,
        log_file_max_mb: Optional[T_CoerceInt] = VARS_CLIENT.log_file_max_mb,
        log_file_name: T_Pathy = VARS_CLIENT.log_file_name,
        log_file_path: T_Pathy = VARS_CLIENT.log_file_path,
        log_file_rotate: T_CoerceBool = VARS_CLIENT.log_file_rotate,
        log_level_api: T_LogLevel = VARS_CLIENT.log_level_api,
        log_level_console: T_LogLevel = VARS_CLIENT.log_level_console,
        log_level_file: T_LogLevel = VARS_CLIENT.log_level_file,
        log_level_package: T_LogLevel = VARS_CLIENT.log_level_package,
        certpath: Optional[T_Pathy] = VARS_CLIENT.certpath,
        certwarn: Optional[T_CoerceBool] = VARS_CLIENT.certwarn,
        certverify: Optional[T_Verify] = VARS_CLIENT.certverify,
        cert_client_both: Optional[T_Pathy] = VARS_CLIENT.cert_client_both,
        cert_client_cert: Optional[T_Pathy] = VARS_CLIENT.cert_client_cert,
        cert_client_key: Optional[T_Pathy] = VARS_CLIENT.cert_client_key,
        headers: Optional[T_Headers] = VARS_CLIENT.headers,
        headers_auth: Optional[T_Headers] = VARS_CLIENT.headers_auth,
        cookies: Optional[T_Cookies] = VARS_CLIENT.cookies,
        timeout_connect: Optional[T_CoerceIntFloat] = VARS_CLIENT.timeout_connect,
        timeout_response: Optional[T_CoerceIntFloat] = VARS_CLIENT.timeout_response,
        proxy_http: Optional[str] = VARS_CLIENT.proxy_http,
        proxy_https: Optional[str] = VARS_CLIENT.proxy_https,
        user_agent: Optional[str] = VARS_CLIENT.user_agent,
        use_env_creds: T_CoerceBool = VARS_CLIENT.use_env_creds,
        use_env_url: T_CoerceBool = VARS_CLIENT.use_env_url,
        use_env_cookies: T_CoerceBool = VARS_CLIENT.use_env_cookies,
        use_env_headers: T_CoerceBool = VARS_CLIENT.use_env_headers,
        use_env_user_agent: T_CoerceBool = VARS_CLIENT.use_env_user_agent,
        use_env_session: T_CoerceBool = VARS_CLIENT.use_env_session,
        default_scheme: str = VARS_CLIENT.default_scheme,
        save_history: T_CoerceBool = VARS_CLIENT.save_history,
        log_body_lines: T_CoerceInt = VARS_CLIENT.log_body_lines,
        log_hide_values: Optional[T_CoerceReListy] = VARS_CLIENT.log_hide_values,
        log_hide_str: Optional[str] = VARS_CLIENT.log_hide_str,
        log_level_http: T_LogLevel = VARS_CLIENT.log_level_http,
        log_level_urllib: T_LogLevel = VARS_CLIENT.log_level_urllib,
        log_level_request_attrs: T_LogLevel = VARS_CLIENT.log_level_request_attrs,
        log_level_response_attrs: T_LogLevel = VARS_CLIENT.log_level_response_attrs,
        log_level_request_body: T_LogLevel = VARS_CLIENT.log_level_request_body,
        log_level_response_body: T_LogLevel = VARS_CLIENT.log_level_response_body,
        log_request_attrs: Optional[List[str]] = VARS_CLIENT.log_request_attrs,
        log_request_body: T_CoerceBool = VARS_CLIENT.log_request_body,
        log_response_attrs: Optional[List[str]] = VARS_CLIENT.log_response_attrs,
        log_response_body: T_CoerceBool = VARS_CLIENT.log_response_body,
    ):
        """Client for interacting with Axonius.

        Notes:
            Must supply key & secret OR username & password as OS env vars or arguments!

        Args:
            url (Optional[T_Url], optional): URL, hostname, or IP address of Axonius instance
            key (Optional[str], optional): API Key from account page in Axonius instance
            secret (Optional[str], optional): API Secret from account page in Axonius instance
            username (Optional[str], optional): username
            password (Optional[str], optional): password
            proxy (Optional[str], optional): proxy to use for http and https urls
            wraperror (T_CoerceBool, optional): wrap errors in human friendly way or show full tb
            log_console (T_CoerceBool, optional): enable logging to console
            log_console_date_fmt (str, optional): date format for console logs
            log_console_fmt (str, optional): log format for console logs
            log_file (T_CoerceBool, optional): enable logging to file
            log_file_date_fmt (str, optional): date format for file logs
            log_file_fmt (str, optional): log format for file logs
            log_file_max_files (Optional[T_CoerceInt], optional): maximum log rollovers to keep
            log_file_max_mb (Optional[T_CoerceInt], optional): log rollover trigger size in MB
            log_file_name (T_Pathy, optional): file name to use for file log
            log_file_path (T_Pathy, optional): file path to use for file log
            log_file_rotate (T_CoerceBool, optional): rotate the file log on start
            log_level_api (T_LogLevel, optional): log level for api models
            log_level_console (T_LogLevel, optional): log level for console logs
            log_level_file (T_LogLevel, optional): log level for file logs
            log_level_package (T_LogLevel, optional): log level for entire package
            certpath (Optional[T_Pathy], optional): path to CA bundle file to use
                when verifying certs offered by server (over-rides certverify)
            certwarn (Optional[T_CoerceBool], optional): control insecure warnings
                True=once; False=never; Any=always
            certverify (Optional[T_Verify], optional): raise exception if cert is self-signed
            cert_client_both (Optional[T_Pathy], optional): path containing both client cert
                and unencrypted client cert key to offer to server
            cert_client_cert (Optional[T_Pathy], optional): path containing just client cert
                to offer to server (must also supply cert_client_key)
            cert_client_key (Optional[T_Pathy], optional): path containing just unencrypted
                client cert key to offer to server (must also supply cert_client_cert)
            headers (Optional[T_Headers], optional): headers to send with every request
            headers_auth (Optional[T_Headers], optional): headers for authentication to send
                with every request
            cookies (Optional[T_Cookies], optional): cookies to send with every request
            timeout_connect (Optional[T_CoerceIntFloat], optional): seconds for connect
            timeout_response (Optional[T_CoerceIntFloat], optional): seconds for respons
            proxy_http (Optional[str], optional): proxy to use for http urls, overrides proxy
            proxy_https (Optional[str], optional): proxy to use for https urls, overrides proxy
            user_agent (Optional[str], optional): override default user-agent header
            use_env_creds (T_CoerceBool, optional): if key, secret, username, password not
                supplied, get from OS envs AX_KEY, AX_SECRET, AX_USERNAME, AX_PASSWORD
            use_env_url (T_CoerceBool, optional): if url not supplied, get url from OS env AX_URL
            use_env_cookies (T_CoerceBool, optional): get additional cookies to send with every
                request from CSV str in OS env AX_COOKIES
            use_env_headers (T_CoerceBool, optional): get additional headers to send with every
                request from CSV str in OS env AX_HEADERS
            use_env_user_agent (T_CoerceBool, optional): if user_agent not supplied, get the value
                for the User-Agent header from OS env AX_USER_AGENT
            use_env_session (T_CoerceBool, optional): Merge requests OS env vars and session vars
                with every request
            default_scheme (str, optional): Default scheme to use when parsing url without
                a scheme (https/http)
            save_history (T_CoerceBool, optional): Append all responses to :attr:`HISTORY`
            log_body_lines (T_CoerceInt, optional): Maximum number of lines to log of bodies
            log_hide_values (Optional[T_CoerceReListy], optional): list of str values or regexes
                to hide if they match any key/value pairs of headers or cookies
            log_hide_str (Optional[str], optional): str to use for matches in log_hide_values
            log_level_http (T_LogLevel, optional): log level for this obj
            log_level_urllib (T_LogLevel, optional): log level for urllib
            log_level_request_attrs (T_LogLevel, optional): log level for request attrs
            log_level_response_attrs (T_LogLevel, optional): log level for response attrs
            log_level_request_body (T_LogLevel, optional): log level for request bodies
            log_level_response_body (T_LogLevel, optional): log level for response bodies
            log_request_attrs (Optional[List[str]], optional): attrs to log for requests
            log_request_body (T_CoerceBool, optional): log request body
            log_response_attrs (Optional[List[str]], optional): attrs to log for responses
            log_response_body (T_CoerceBool, optional): log response body

        """
        self.__creds = {"key": key, "secret": secret, "username": username, "password": password}

        self.__init_locals = locals()
        self._kwargs_http = {k: self.__init_locals[k] for k in VARS_HTTP.get_field_names()}
        super().__init__(**self._kwargs_http)

        self.eula_agreed = eula_agreed
        self.use_env_creds = use_env_creds
        self.wraperror = wraperror
        self.log_level_package = log_level_package
        self.log_level_api = log_level_api
        self.log_level_console = log_level_console
        self.log_level_file = log_level_file
        self.log_console_fmt = log_console_fmt
        self.log_console_date_fmt = log_console_date_fmt
        self.log_file_fmt = log_file_fmt
        self.log_file_date_fmt = log_file_date_fmt
        self.log_file_max_files = log_file_max_files
        self.log_file_max_mb = log_file_max_mb
        self.log_file_name = log_file_name
        self.log_file_path = log_file_path
        self.log_file_rotate = log_file_rotate
        self.log_file = log_file
        self.log_console = log_console

    def __str__(self) -> str:
        """Show object info."""
        banner = f"[{self.env_banner}]" if is_str(self.env_banner) else ""
        pkg_ver = f"API Client v{VERSION}"
        msg = [f"Not connected to {self.url!r}"]

        if self.started:
            msg = [
                f"Connected to {self.url!r}",
                f"version {self._about_version}",
                f"(RELEASE DATE: {self._about_build_date})",
            ]

        bits = [x for x in [*msg, pkg_ver, banner] if x]
        return " ".join(bits)

    # XXX
    """
    def login()
    update_dot_env: bool = True
    dot_env_path: T_Pathy = INIT_DOTENV

    """

    def start(self):
        """Connect to and authenticate with Axonius."""
        if not self.started:
            sysinfo_dump = json_dump(sysinfo())
            self.LOG.debug(f"SYSTEM INFO: {sysinfo_dump}")

            try:
                self.AUTH.login()
            except Exception as exc:
                if not self.wraperror:
                    raise

                pre = f"Unable to connect to {self.url!r}"

                if isinstance(exc, requests.ConnectTimeout):
                    cnxexc = ConnectError(
                        f"{pre}: connection timed out after {self.timeout_connect} seconds"
                    )
                elif isinstance(exc, requests.ConnectionError):
                    cnxexc = ConnectError(f"{pre}: {self._get_exc_reason(exc=exc)}")
                elif isinstance(exc, InvalidCredentials):
                    cnxexc = ConnectError(f"{pre}: Invalid Credentials supplied")
                else:
                    cnxexc = ConnectError(f"{pre}: {exc}")
                cnxexc.exc = exc
                raise cnxexc

            self._started = True
            self.LOG.info(str(self))

    @property
    def started(self) -> bool:
        """Check if :meth:`start` has been called."""
        return getattr(self, "_started", False)

    @property
    def wraperror(self) -> bool:
        """Wrap errors during :meth:`start` in human friendly way or show full traceback."""
        return self._proper("wraperror")

    @wraperror.setter
    def wraperror(self, value: bool):
        self._wraperror = coerce_bool(obj=value, src_arg="wraperror", src_obj=self)

    @property
    def eula_agreed(self) -> bool:
        """EULA has been read and accepted."""
        return self._proper("eula_agreed")

    @eula_agreed.setter
    def eula_agreed(self, value: bool):
        self._eula_agreed = coerce_bool(obj=value, src_arg="eula_agreed", src_obj=self)

    @property
    def log_file(self) -> bool:
        """Enable logging to a file."""
        return self._proper("log_file")

    @log_file.setter
    def log_file(self, value: bool):
        self._log_file = coerce_bool(obj=value, src_arg="log_file", src_obj=self)
        if self._log_file:
            self.HANDLER_FILE = add_file(
                obj=PACKAGE_LOG,
                level=self.log_level_file,
                file_path=self.log_file_path,
                file_name=self.log_file_name,
                max_mb=self.log_file_max_mb,
                max_files=self.log_file_max_files,
                fmt=self.log_file_fmt,
                datefmt=self.log_file_date_fmt,
            )
            if self.log_file_rotate:
                self._rotate_file_log()
        else:
            if isinstance(self.HANDLER_FILE, logging.Handler):
                del_file(obj=PACKAGE_LOG)
                self.HANDLER_FILE = None

    @property
    def log_file_rotate(self) -> bool:
        """Rotate the file log when starting file logging."""
        return self._proper("log_file_rotate")

    @log_file_rotate.setter
    def log_file_rotate(self, value: bool):
        self._log_file_rotate = coerce_bool(obj=value, src_arg="log_file_rotate", src_obj=self)

    @property
    def log_file_fmt(self) -> Optional[str]:
        """Pass."""
        return self._proper("log_file_fmt")

    @log_file_fmt.setter
    def log_file_fmt(self, value: Optional[str]):
        self._log_file_fmt = value
        if self.HANDLER_FILE:
            self.HANDLER_FILE.setFormatter(
                logging.Formatter(fmt=self.log_file_fmt, datefmt=self.log_file_date_fmt)
            )

    @property
    def log_file_max_files(self) -> Optional[int]:
        """Pass."""
        return self._proper("log_file_max_files")

    @log_file_max_files.setter
    def log_file_max_files(self, value: Optional[T_CoerceInt]):
        self._log_file_max_files = coerce_int(
            obj=value,
            min_value=1,
            allow_none=True,
            allow_none_strs=True,
            src_arg="log_file_max_files",
            src_obj=self,
        )
        if self.HANDLER_FILE:
            self.HANDLER_FILE.backupCount = self.log_file_max_files

    @property
    def log_file_max_mb(self) -> Optional[str]:
        """Pass."""
        return self._proper("log_file_max_mb")

    @log_file_max_mb.setter
    def log_file_max_mb(self, value: Optional[T_CoerceInt]):
        self._log_file_max_mb = coerce_int(
            obj=value,
            min_value=1,
            allow_none=True,
            allow_none_strs=True,
            src_arg="log_file_max_mb",
            src_obj=self,
        )
        if self.HANDLER_FILE:
            self.HANDLER_FILE.maxBytes = self.log_file_max_mb * 1024 * 1024

    @property
    def log_file_name(self) -> T_Pathy:
        """Pass."""
        return self._proper("log_file_name")

    @log_file_name.setter
    def log_file_name(self, value: T_Pathy):
        """Pass."""
        self._log_file_name = value

    @property
    def log_file_path(self) -> pathlib.Path:
        """Pass."""
        return self._proper("log_file_path")

    @log_file_path.setter
    def log_file_path(self, value: T_Pathy):
        """Pass."""
        resolved = pathify(path=value)
        resolved = resolved.parent if resolved.is_file() else resolved
        self._log_file_path = resolved

    @property
    def log_console(self) -> bool:
        """Enable logging to the console via STDERR."""
        return self._proper("log_console")

    @log_console.setter
    def log_console(self, value: bool):
        self._log_console = coerce_bool(obj=value, src_arg="log_console", src_obj=self)
        if self._log_console:
            self.HANDLER_CON = add_stderr(
                obj=PACKAGE_LOG,
                level=self.log_level_console,
                fmt=self.log_console_fmt,
                datefmt=self.log_console_date_fmt,
            )
        else:
            if isinstance(self.HANDLER_CON, logging.Handler):
                del_stderr(obj=PACKAGE_LOG)
                self.HANDLER_CON = None

    @property
    def log_console_fmt(self) -> Optional[str]:
        """Pass."""
        return self._proper("log_console_fmt")

    @log_console_fmt.setter
    def log_console_fmt(self, value: Optional[str]):
        self._log_console_fmt = value
        if isinstance(self.HANDLER_CON, logging.Handler):
            self.HANDLER_CON.setFormatter(
                logging.Formatter(fmt=self.log_console_fmt, datefmt=self.log_console_date_fmt)
            )

    @property
    def log_console_date_fmt(self) -> Optional[str]:
        """Pass."""
        return self._proper("log_console_date_fmt")

    @log_console_date_fmt.setter
    def log_console_date_fmt(self, value: Optional[str]):
        self._log_console_date_fmt = value
        if isinstance(self.HANDLER_CON, logging.Handler):
            self.HANDLER_CON.setFormatter(
                logging.Formatter(fmt=self.log_console_fmt, datefmt=self.log_console_date_fmt)
            )

    @property
    def log_level_api(self) -> str:
        """Log level assigned to all api models."""
        return self._proper("log_level_api")

    @log_level_api.setter
    def log_level_api(self, value: T_LogLevel):
        self._log_level_api = set_get_log_level(
            obj=PACKAGE_LOG.getChild("api"), level=value, children=True
        )

    @property
    def log_level_console(self) -> str:
        """Log level assigned to :attr:`HANDLER_CON`."""
        return self._proper("log_level_console")

    @log_level_console.setter
    def log_level_console(self, value: T_LogLevel):
        self._log_level_console = str_level(value)
        if isinstance(self.HANDLER_CON, logging.Handler):
            set_log_level(obj=self.HANDLER_CON, level=self._log_level_console)

    @property
    def log_level_file(self) -> str:
        """Log level assigned to :attr:`HANDLER_FILE`."""
        return self._proper("log_level_file")

    @log_level_file.setter
    def log_level_file(self, value: T_LogLevel):
        self._log_level_file = str_level(value)
        if isinstance(self.HANDLER_FILE, logging.Handler):
            set_log_level(obj=self.HANDLER_FILE, level=self._log_level_file)

    @property
    def log_level_package(self) -> str:
        """Log level assigned to entire package."""
        return self._proper("log_level_package")

    @log_level_package.setter
    def log_level_package(self, value: T_LogLevel):
        self._log_level_package = set_get_log_level(obj=PACKAGE_LOG, level=value)

    @property
    def use_env_creds(self) -> bool:
        """Get key, secret, username, password from OS env vars if not supplied."""
        return self._proper("use_env_creds")

    @use_env_creds.setter
    def use_env_creds(self, value: T_CoerceBool):
        self._use_env_creds = coerce_bool(obj=value, src_arg="use_env_creds", src_obj=self)

    @property
    def env_banner(self) -> str:
        """Value from OS Env AX_BANNER."""
        ret = self.__env_values_client.get("banner")
        return ret if is_str(ret) else ""

    @property
    def signup(self) -> Signup:
        """Work with signup endpoints."""
        return self._model(Signup)

    @property
    def users(self) -> Users:
        """Work with user assets."""
        return self._model(Users)

    @property
    def vulnerabilities(self) -> Users:
        """Work with user assets."""
        return self._model(Vulnerabilities)

    @property
    def devices(self) -> Devices:
        """Work with device assets."""
        return self._model(Devices)

    @property
    def adapters(self) -> Adapters:
        """Work with adapters and adapter connections."""
        return self._model(Adapters)

    @property
    def instances(self) -> Instances:
        """Work with instances."""
        return self._model(Instances)

    @property
    def activity_logs(self) -> ActivityLogs:
        """Work with activity logs."""
        return self._model(ActivityLogs)

    @property
    def remote_support(self) -> RemoteSupport:
        """Work with configuring remote support."""
        return self._model(RemoteSupport)

    @property
    def dashboard(self) -> Dashboard:
        """Work with dashboards and discovery cycles."""
        return self._model(Dashboard)

    @property
    def enforcements(self) -> Enforcements:
        """Work with Enforcement Center."""
        return self._model(Enforcements)

    @property
    def system_users(self) -> SystemUsers:
        """Work with system users."""
        return self._model(SystemUsers)

    @property
    def system_roles(self) -> SystemRoles:
        """Work with system roles."""
        return self._model(SystemRoles)

    @property
    def meta(self) -> Meta:
        """Work with instance metadata."""
        return self._model(Meta)

    @property
    def settings_ip(self) -> SettingsIdentityProviders:
        """Work with identity providers settings."""
        return self._model(SettingsIdentityProviders)

    @property
    def settings_global(self) -> SettingsGlobal:
        """Work with core system settings."""
        return self._model(SettingsGlobal)

    @property
    def settings_gui(self) -> SettingsGui:
        """Work with gui system settings."""
        return self._model(SettingsGui)

    @property
    def settings_lifecycle(self) -> SettingsLifecycle:
        """Work with lifecycle system settings."""
        return self._model(SettingsLifecycle)

    @property
    def openapi(self) -> OpenAPISpec:
        """Work with the OpenAPI specification file."""
        return self._model(OpenAPISpec)

    @property
    def data_scopes(self) -> DataScopes:
        """Work with data scopes."""
        return self._model(DataScopes)

    @staticmethod
    def jdump(obj, **kwargs):  # pragma: no cover
        """JSON dump utility."""
        print(json_reload(obj, **kwargs))

    @property
    def _about(self) -> dict:
        """Pass."""
        return self.meta.about()

    @property
    def _about_build_date(self) -> str:
        """Pass."""
        return self._about.get("Build Date", "")

    @property
    def _about_version(self) -> str:
        """Pass."""
        about = self._about
        version = about.get("Version", "") or about.get("Installed Version", "") or "DEMO"
        return version.replace("_", ".")

    @classmethod
    def _get_exc_reason(cls, exc: Exception) -> str:
        """Trim exceptions down to a more user friendly display.

        Uses :attr:`REASON_RES` to do regex substituions.
        """
        reason = str(exc)
        for reason_re in REASON_RES:
            try:
                if reason_re.search(reason):
                    return reason_re.sub(r"\1", reason).rstrip("')")
            except Exception:
                continue
        return reason

    def _model(self, model: Type[ApiModel]) -> ApiModel:
        """Pass."""
        self.start()
        name = model.__name__
        prop = f"_model_{name}"
        if not hasattr(self, prop):
            obj = model(client=self, log_level=self.log_level_api)
            setattr(self, prop, obj)
        return getattr(self, prop)

    def _rotate_file_log(self) -> bool:
        """Pass."""
        if isinstance(self.HANDLER_FILE, logging.Handler):
            self.LOG.info("Forcing file logs to rotate")
            self.HANDLER_FILE.flush()
            self.HANDLER_FILE.doRollover()
            self.LOG.info("Forced file logs to rotate")
            return True
        return False

    def __resolve_cred(self, cred: str, **kwargs) -> Optional[str]:
        """Pass."""
        creds = kwargs.get("creds")
        creds = creds if isinstance(creds, dict) else {}

        kw = creds.get(cred)
        if is_str(kw):
            return kw

        init = self.__creds.get(cred)
        if is_str(init):
            return init

        env = self.__env_values_client.get(cred)
        if self.use_env_creds and is_str(env):
            return env
        return None

    def __resolve_creds(self, **kwargs) -> dict:
        """Pass."""
        return {k: self.__resolve_cred(k, **kwargs) for k in CREDS}

    def __get_headers_auth(self, **kwargs) -> Optional[dict]:
        """Pass."""
        ret = super.__get_headers_auth(**kwargs)
        # XXX exceptions will log request/response body
        auth_required = kwargs.get("auth_required", True)
        rcreds = self.__resolve_creds(**kwargs)
        rkey = rcreds.get("key")
        rsecret = rcreds.get("secret")
        rusername = rcreds.get("username")
        rpassword = rcreds.get("password")

        if is_str(rkey) and is_str(rsecret):
            ret.update({"api-key": rkey, "api-secret": rsecret})
        elif is_str(rusername) and is_str(rpassword):
            creds = {"user_name": rusername, "password": rpassword}
            print(f"{creds} needs login dance!")
        else:
            if auth_required:
                raise ClientError("Must supply key and secret OR username and password")
        return ret

        """
        to just test connection:
        GET api/get_environment_name (no auth)
        GET api/get_login_options (no auth)

        GET api/login  (auth, get_current_user object)
        GET api/settings/meta/about (auth)
        GET api/settings/api_key (auth) get users api key and secret
        POST api/login (unauth, send creds)

        step1: check connection by getting unauthenticated calls
        step1a: RESPONSE method=GET,  path=api/get_environment_name, use_headers_auth=False
        step2: log(step1)
        step3: get login options (unauth)
        step3a: RESPONSE method=GET, path=api/get_login_options, use_headers_auth=False
        step4: check login options
        step4a: if step3['meta']...samlpath and not using key/secret, throw exc
        step5: send login request with username/password creds
        step5a: REQUEST POST api/login "login_schema"
            {"user_name": "admin", "password": "admin", "remember_me": false}
        step5b: RESPONSE "metadata_schema":
            "meta": {"request_eula": True}
        step6: check if api asks user to accept eula
        step6a: request_eula = step5['meta'].get("request_eula", False)
        step7: if request_eula and not self.eula_agreed, throw exc with constants.general.TERMS
        step8: if request_eula and self.eula_agreed
        step8a: REQUEST POST api/login "login_schema"
            {"user_name": "admin", "password": "admin", "remember_me": false, "eula_agreed": true}
        step8b: RESPONSE "metadata_schema":
            "meta": {"access_token": "...", "refresh_token": "..."}
        step9: get access token from step5 or step8
        step9a: access_token = (step5 or step8).get('meta', {}).get('access_token')
        step10: if not is_str(access_token), throw InvalidCredentials exc
        step11: if is_str(access_token), login successful, get api key and secret
        step11a: GET api/settings/api_key
            headers = {'Authorization': = f'Bearer {access_token}'}
        step11b: {'api_key': '', 'api_secret': ''}
        step12: self.__creds[key] = response step11['api_key']
        step13: self.__creds[secret] = response step11['api_secret']
        step14: validate login by getting info on current user
        step14a: REQUEST GET api/login
        step14b: RESPONSE
        step15: log(step14)
        step16: if not self.update_dot_env, stop
        step16a: if self.update_dot_env and DOT_ENV_SUPPLIED set_dot_env
        step16b: if self.update_dot_env and NOT DOT_ENV_SUPPLIED, throw arning
        step16c: set_dot_env = AX_KEY=step11['api_key'], AX_SECRET=step11['api_secret']

        note: add axonapi.DOT_ENV_SUPPLIED = DOT_ENV.is_file()
        """

    @property
    def __env_values_client(self) -> dict:
        """Pass."""
        if not hasattr(self, "__ENV_VALUES_CLIENT"):
            self.__ENV_VALUES_CLIENT = get_env_values_client()
        return self.__ENV_VALUES_CLIENT
