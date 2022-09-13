# -*- coding: utf-8 -*-
"""HTTP client."""
import logging
import pathlib
from typing import Any, List, Optional, Tuple, Union

import requests
from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict

from . import cert_human
from .constants.http import VARS_HTTP, AttrMaps
from .constants.typer import (
    T_CoerceBool,
    T_CoerceInt,
    T_CoerceIntFloat,
    T_CoerceRe,
    T_CoerceReListy,
    T_Cookies,
    T_Headers,
    T_LogLevel,
    T_Pathy,
    T_Requests,
    T_Verify,
)
from .exceptions import HttpError, InvalidCredentials, ResponseNotOk
from .logs import get_log_method, get_obj_logger, set_get_log_level, str_level
from .parsers.url_parser import T_Url, UrlParser
from .setup_env import ENV_KEYS, get_env_values_http
from .tools import (
    coerce_bool,
    coerce_int,
    coerce_int_float,
    coerce_re,
    combo_dicts,
    hide_values,
    is_str,
    is_url_path_match,
    join_url,
    json_log,
    listify,
    lowish,
    parse_csv_str,
    path_read,
    warn_toggle,
)
from .version import __version__

cert_human.ssl_capture.inject_into_urllib3()


class Http:
    """HTTP client that wraps around around :obj:`requests.Session`."""

    VARS = VARS_HTTP

    session: requests.Session = None
    """requests session object"""

    LAST_REQUEST: Optional[requests.PreparedRequest] = None
    """last request sent"""

    LAST_RESPONSE: Optional[requests.Response] = None
    """last response received"""

    HISTORY: List[requests.Response] = None
    """all responses received if :attr:`save_history` is True"""

    LOG: logging.Logger = None
    """Logger object."""

    def __init__(
        self,
        url: Optional[T_Url] = VARS_HTTP.url,
        certpath: Optional[T_Pathy] = VARS_HTTP.certpath,
        certwarn: Optional[T_CoerceBool] = VARS_HTTP.certwarn,
        certverify: Optional[T_Verify] = VARS_HTTP.certverify,
        cert_client_both: Optional[T_Pathy] = VARS_HTTP.cert_client_both,
        cert_client_cert: Optional[T_Pathy] = VARS_HTTP.cert_client_cert,
        cert_client_key: Optional[T_Pathy] = VARS_HTTP.cert_client_key,
        headers: Optional[T_Headers] = VARS_HTTP.headers,
        headers_auth: Optional[T_Headers] = VARS_HTTP.headers_auth,
        cookies: Optional[T_Cookies] = VARS_HTTP.cookies,
        timeout_connect: Optional[T_CoerceIntFloat] = VARS_HTTP.timeout_connect,
        timeout_response: Optional[T_CoerceIntFloat] = VARS_HTTP.timeout_response,
        proxy: Optional[str] = VARS_HTTP.proxy,
        proxy_http: Optional[str] = VARS_HTTP.proxy_http,
        proxy_https: Optional[str] = VARS_HTTP.proxy_https,
        user_agent: Optional[str] = VARS_HTTP.user_agent,
        use_env_url: T_CoerceBool = VARS_HTTP.use_env_url,
        use_env_cookies: T_CoerceBool = VARS_HTTP.use_env_cookies,
        use_env_headers: T_CoerceBool = VARS_HTTP.use_env_headers,
        use_env_user_agent: T_CoerceBool = VARS_HTTP.use_env_user_agent,
        use_env_session: T_CoerceBool = VARS_HTTP.use_env_session,
        default_scheme: str = VARS_HTTP.default_scheme,
        save_history: T_CoerceBool = VARS_HTTP.save_history,
        log_body_lines: T_CoerceInt = VARS_HTTP.log_body_lines,
        log_hide_urls: Optional[T_CoerceReListy] = VARS_HTTP.log_hide_urls,
        log_hide_matches: Optional[T_CoerceReListy] = VARS_HTTP.log_hide_matches,
        log_hide_str: Optional[str] = VARS_HTTP.log_hide_str,
        log_level_http: T_LogLevel = VARS_HTTP.log_level_http,
        log_level_urllib: T_LogLevel = VARS_HTTP.log_level_urllib,
        log_level_request_attrs: T_LogLevel = VARS_HTTP.log_level_request_attrs,
        log_level_response_attrs: T_LogLevel = VARS_HTTP.log_level_response_attrs,
        log_level_request_body: T_LogLevel = VARS_HTTP.log_level_request_body,
        log_level_response_body: T_LogLevel = VARS_HTTP.log_level_response_body,
        log_request_attrs: Optional[List[str]] = VARS_HTTP.log_request_attrs,
        log_request_body: T_CoerceBool = VARS_HTTP.log_request_body,
        log_response_attrs: Optional[List[str]] = VARS_HTTP.log_response_attrs,
        log_response_body: T_CoerceBool = VARS_HTTP.log_response_body,
    ):
        """HTTP client that wraps around :obj:`requests.Session`.

        Args:
            url (Optional[T_Url], optional): URL, hostname, or IP address of Axonius instance
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
            proxy (Optional[str], optional): proxy to use for http and https urls
            proxy_http (Optional[str], optional): proxy to use for http urls, overrides proxy
            proxy_https (Optional[str], optional): proxy to use for https urls, overrides proxy
            user_agent (Optional[str], optional): override default user-agent header
            use_env_url (T_CoerceBool, optional): get url from OS env AX_URL
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
            log_hide_urls (Optional[T_CoerceReListy], optional): list of str values or regexes
                to control hiding request and response body dict key values
            log_hide_matches (Optional[T_CoerceReListy], optional): list of str values or regexes
                to hide if they match any key/value pairs of any dict like object
            log_hide_str (Optional[str], optional): str to use for matches in log_hide_matches
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
        self._url_original = url
        self.__headers_auth = (
            headers_auth if isinstance(headers_auth, T_Headers) else CaseInsensitiveDict()
        )

        self.LOG = get_obj_logger(obj=self)
        self.use_env_url = use_env_url
        self.use_env_cookies = use_env_cookies
        self.use_env_headers = use_env_headers
        self.use_env_user_agent = use_env_user_agent
        self.use_env_session = use_env_session
        self.default_scheme = default_scheme
        self.cert_client_both = cert_client_both
        self.cert_client_cert = cert_client_cert
        self.cert_client_key = cert_client_key
        self.certverify = self.certverify
        self.certpath = certpath
        self.certwarn = certwarn
        self.cookies = cookies
        self.headers = headers
        self.proxy = proxy
        self.proxy_http = proxy_http
        self.proxy_https = proxy_https
        self.timeout_connect = timeout_connect
        self.timeout_response = timeout_response
        self.log_body_lines = log_body_lines
        self.log_hide_matches = log_hide_matches
        self.log_hide_urls = log_hide_urls
        self.log_hide_str = log_hide_str
        self.log_level_http = log_level_http
        self.log_level_urllib = log_level_urllib
        self.log_level_request_attrs = log_level_request_attrs
        self.log_level_response_attrs = log_level_response_attrs
        self.log_level_request_body = log_level_request_body
        self.log_level_response_body = log_level_response_body
        self.log_request_attrs = log_request_attrs
        self.log_request_body = log_request_body
        self.log_response_attrs = log_response_attrs
        self.log_response_body = log_response_body
        self.save_history = save_history
        self.user_agent = user_agent
        self.url = url
        self._reset()

    def request(
        self,
        path: Optional[str] = None,
        route: Optional[str] = None,
        method: str = "get",
        stream: Any = None,
        data: Any = None,
        params: Any = None,
        json: Any = None,
        files: Any = None,
        auth: Any = None,
        hooks: Any = None,
        reset_session: bool = False,
        **kwargs,
    ) -> requests.Response:
        """Create, prepare, and then send a request using :attr:`session`.

        Args:
            path (Optional[str], optional): path to append to :attr:`url` as (url, path, route)
            route (Optional[str], optional): route to append to :attr:`url` as (url, path, route)
            method (str, optional): HTTP method to use
            stream (Any, optional): passthru to request
            data (Any, optional): passthru to request
            params (Any, optional): passthru to request
            json (Any, optional): passthru to request
            files (Any, optional): passthru to request
            auth (Any, optional): passthru to request
            hooks (Any, optional): passthru to request
            proxies: manually specify proxies, overriding proxy_http and proxy_https
            use_cookies (bool, optional): Include :attr:`cookies` in request cookies
            reset_session (bool, optional): close :attr:`session` and recreate
            **kwargs: override http attributes
                cert (T_Pathy): override :method:`_get_request_cert`
                verify (T_Verify): override :method:`_get_request_verify`
                timeout_connect (int, float): override :attr:`timeout_connect`
                timeout_response (int, float): override :attr:`timeout_response`
                timeout (tuple): manually specify timeout, ignores timeout_connect/timeout_response
                proxy (str): override :attr:`proxy`
                proxy_http (str): override :attr:`proxy_http`
                proxy_https (str): override :attr:`proxy_https`
                use_env_session (bool): override :attr:`use_env_session`
                user_agent (str): override :attr:`user_agent`
                log_body (bool): override :attr:`log_request_body` and :attr:`log_response_body`
                log_request_body (bool): override :attr:`log_request_body`
                log_response_body (bool): override :attr:`log_response_body`
                log_level_request_attrs (str): override :attr:`log_level_request_attrs`
                log_level_request_body (str): override :attr:`log_level_request_body`
                log_level_response_attrs (str): override :attr:`log_level_response_attrs`
                log_level_response_body (str): override :attr:`log_level_response_body`
                use_headers (bool): Include :attr:`headers` in request
                use_headers_auth (bool): Include :attr:`headers_auth` in request
                use_cookies (bool): Include :attr:`cookies` in request
                headers: additional headers to send
                cookies: additional cookies to send

        Returns:
            :obj: `requests.Response`
        """
        if reset_session is True or not isinstance(self.session, requests.Session):
            self._reset()
        url = join_url(self.url, path, route)
        use_env_session = kwargs.get("use_env_session", self.use_env_session)
        save_history = kwargs.get("save_history", self.save_history)
        rcert = self._get_request_cert(**kwargs)
        rverify = self._get_request_verify(**kwargs)
        rtimeout = self._get_request_timeout(**kwargs)
        rproxies = self._get_request_proxies(**kwargs)
        rcookies = self._get_request_cookies(**kwargs)
        rheaders = self._get_request_headers(**kwargs)
        send_args = {"proxies": rproxies, "stream": stream, "verify": rverify, "cert": rcert}
        self.LAST_REQUEST = request = requests.Request(
            url=url,
            method=method,
            data=data,
            headers=rheaders,
            params=params,
            json=json,
            files=files,
            cookies=rcookies,
            auth=auth,
            hooks=hooks,
        )
        self.LAST_REQUEST = prequest = self.session.prepare_request(request=request)
        if use_env_session:
            send_args = self.session.merge_environment_settings(url=prequest.url, **send_args)
        send_args["timeout"] = rtimeout
        self._emit_request(**combo_dicts(kwargs, value=prequest, send_args=send_args))
        self.LAST_RESPONSE = response = self._send(request=prequest, **send_args)
        if save_history:
            self.HISTORY.append(response)
        self._emit_request(**combo_dicts(kwargs, value=response, send_args=send_args))
        self._check_status(**combo_dicts(kwargs, response=response))
        return response

    # XXX From ApiEndpoint
    def _check_status(self, response: requests.Response, **kwargs):
        """Check the status code of a response.

        Args:
            response (requests.Response): response to handle
            check_status_hook (Optional[callable], optional): callable to perform
                extra checks of response status that takes args: http, response, kwargs
            **kwargs: Passed to `check_status_hook` if supplied, if hook returns truthy
                no more status checks are done

        Notes:
            If check_status_hook returns True, the rest of the check_response_status
            workflow will be skipped

        Raises:
            InvalidCredentials: if response has has a 401 status code
            ResponseNotOk: if response has a bad status code
        """
        check_status_hook = kwargs.get("check_status_hook")  # XXX
        check_status = kwargs.get("check_status")  # XXX

        if callable(check_status_hook):
            hook_ret = check_status_hook(http=self, response=response, **kwargs)
            if hook_ret is True:
                return

        if not check_status:
            return

        msgs = [
            f"Response has a bad HTTP status code: {response.status_code}",
            # f"While in {self}",
            # XXX need to wrap this in connect with request_endpoint?
        ]

        if response.status_code == 401:
            msgs.append("Invalid credentials")
            raise InvalidCredentials(msg="\n".join(msgs), response=response)

        try:
            response.raise_for_status()
        except Exception as exc:
            raise ResponseNotOk(msg="\n".join(msgs), response=response, exc=exc)

    @property
    def url(self) -> Optional[str]:
        """URL after parsing."""
        return getattr(self, "_url_parsed", self._url_original)

    @url.setter
    def url(self, value: Optional[T_Url]):
        self._url_original = value
        resolved = None
        if isinstance(value, UrlParser):
            resolved = value
        elif is_str(value):
            resolved = UrlParser(url=value, default_scheme=self.default_scheme)
        elif self.use_env_url and is_str(self.env_url):
            resolved = UrlParser(url=self.env_url, default_scheme=self.default_scheme)

        self._url = resolved

        if not isinstance(resolved, UrlParser):
            raise HttpError(
                f"Must supply value for url, supplied {value!r} type {type(value)}"
                f"\n use_env_url={self.use_env_url}, env_url {ENV_KEYS.URL}={self.env_url!r}"
            )

        self._url_parsed = resolved.url

    @property
    def default_scheme(self) -> Optional[str]:
        """Scheme to use when parsing url if none supplied."""
        return self._proper("default_scheme")

    @default_scheme.setter
    def default_scheme(self, value: str):
        self._default_scheme = value

    @property
    def proxy(self) -> Optional[str]:
        """Proxy to use for all requests."""
        return self._proper("proxy")

    @proxy.setter
    def proxy(self, value: Optional[T_Url]):
        self._proxy = self._parse_url(value=value, default_scheme=self.default_scheme)

    @property
    def proxy_http(self) -> Optional[str]:
        """Proxy to use for http:// requests."""
        ret = self._proper("proxy_http")
        return ret if is_str(ret) else self.proxy

    @proxy_http.setter
    def proxy_http(self, value: Optional[T_Url]):
        self._proxy_http = self._parse_url(value=value, default_scheme="http")

    @property
    def proxy_https(self) -> Optional[str]:
        """Proxy to use for https:// requests."""
        ret = self._proper("proxy_https")
        return ret if is_str(ret) else self.proxy

    @proxy_https.setter
    def proxy_https(self, value: Optional[T_Url]):
        self._proxy_https = self._parse_url(value=value, default_scheme="https")

    @property
    def user_agent(self) -> str:
        """Value to use in User-Agent header.

        If no user_agent supplied to this class, try to get one from OS environment variable
        AX_USER_AGENT if use_env_user_agent, else wise fallback to user_agent_default
        """
        ret = self._proper("user_agent")

        if not is_str(ret):
            if self.use_env_user_agent and is_str(self.env_user_agent):
                ret = self.env_user_agent
            else:
                ret = self.user_agent_default
        return ret

    @user_agent.setter
    def user_agent(self, value: Optional[str]):
        self._user_agent = value

    @property
    def user_agent_default(self) -> str:
        """Value to use in User-Agent header if none provided."""
        return f"{self._objid}/{__version__}"

    @property
    def cookies(self) -> T_Cookies:
        """Cookies to send with every request."""
        if not hasattr(self, "_cookies"):
            self._cookies = RequestsCookieJar()
        return self._cookies

    @cookies.setter
    def cookies(self, value: Optional[T_Cookies]):
        self._cookies = value if isinstance(value, T_Cookies) else RequestsCookieJar()

    @property
    def headers(self) -> T_Headers:
        """Headers to send with every request."""
        if not hasattr(self, "_headers"):
            self._headers = CaseInsensitiveDict()
        return self._headers

    @headers.setter
    def headers(self, value: Optional[T_Headers]):
        self._headers = value if isinstance(value, T_Headers) else CaseInsensitiveDict()

    @property
    def certpath(self) -> Optional[pathlib.Path]:
        """Path to SSL Certificate bundle to use to verify certs offered by URL."""
        return self._proper("certpath")

    @certpath.setter
    def certpath(self, value: Optional[T_Pathy]):
        self._certpath = self._parse_file(value)

    @property
    def certverify(self) -> Optional[T_Verify]:
        """Enable/disable SSL verification (certpath overrides this if supplied)."""
        return self._proper("certverify")

    @certverify.setter
    def certverify(self, value: Optional[T_Verify]):
        self._certverify = value

    @property
    def cert_client_both(self) -> Optional[pathlib.Path]:
        """Path to SSL client certificate with both cert & key."""
        return self._proper("cert_client_both")

    @cert_client_both.setter
    def cert_client_both(self, value: Optional[T_Pathy]):
        self._cert_client_both = self._parse_file(value)

    @property
    def cert_client_key(self) -> Optional[pathlib.Path]:
        """Path to SSL client certificate with key only."""
        return self._proper("cert_client_key")

    @cert_client_key.setter
    def cert_client_key(self, value: Optional[T_Pathy]):
        self._cert_client_key = self._parse_file(value)

    @property
    def cert_client_cert(self) -> Optional[pathlib.Path]:
        """Path to SSL client certificate with cert only.."""
        return self._proper("cert_client_cert")

    @cert_client_cert.setter
    def cert_client_cert(self, value: Optional[T_Pathy]):
        self._cert_client_cert = self._parse_file(value)

    @property
    def log_hide_urls(self) -> List[T_CoerceRe]:
        """Hide body values of any URL path fragments that match supplied strs or patterns."""
        return self._proper("log_hide_urls")

    @log_hide_urls.setter
    def log_hide_urls(self, value: Optional[T_CoerceReListy]):
        self._log_hide_urls = coerce_re(value=value, convert_csv=True)

    @property
    def log_hide_matches(self) -> List[T_CoerceRe]:
        """List of keys to hide values of when logging headers/cookies."""
        return self._proper("log_hide_matches")

    @log_hide_matches.setter
    def log_hide_matches(self, value: Optional[T_CoerceReListy]):
        self._log_hide_values = coerce_re(value=value, convert_csv=True)

    @property
    def log_hide_str(self) -> Optional[str]:
        """Value to use when hiding values of keys of headers/cookies."""
        return self._proper("log_hide_str")

    @log_hide_str.setter
    def log_hide_str(self, value: Optional[str]):
        self._log_hide_str = value

    @property
    def use_env_cookies(self) -> bool:
        """Get additional cookies to send with every request from CSV str in OS env AX_COOKIES."""
        return self._proper("use_env_cookies")

    @use_env_cookies.setter
    def use_env_cookies(self, value: T_CoerceBool):
        self._use_env_cookies = coerce_bool(obj=value, src_arg="use_env_cookies", src_obj=self)

    @property
    def use_env_headers(self) -> bool:
        """Get additional headers to send with every request from CSV str in OS env AX_HEADERS."""
        return self._proper("use_env_headers")

    @use_env_headers.setter
    def use_env_headers(self, value: T_CoerceBool):
        self._use_env_headers = coerce_bool(obj=value, src_arg="use_env_headers", src_obj=self)

    @property
    def use_env_url(self) -> bool:
        """Get url from OS env AX_URL if none supplied."""
        return self._proper("use_env_url")

    @use_env_url.setter
    def use_env_url(self, value: T_CoerceBool):
        self._use_env_url = coerce_bool(obj=value, src_arg="use_env_url", src_obj=self)

    @property
    def use_env_user_agent(self) -> bool:
        """Get user_agent from OS env AX_USER_AGENT if none supplied."""
        return self._proper("use_env_user_agent")

    @use_env_user_agent.setter
    def use_env_user_agent(self, value: T_CoerceBool):
        self._use_env_user_agent = coerce_bool(
            obj=value, src_arg="use_env_user_agent", src_obj=self
        )

    @property
    def use_env_session(self) -> bool:
        """Merge request variables with requests package OS env vars + session."""
        return self._proper("use_env_session")

    @use_env_session.setter
    def use_env_session(self, value: T_CoerceBool):
        self._use_env_session = coerce_bool(obj=value, src_arg="use_env_session", src_obj=self)

    @property
    def save_history(self) -> bool:
        """Responses get appended to :attr:`HISTORY`."""
        return self._proper("save_history")

    @save_history.setter
    def save_history(self, value: T_CoerceBool):
        self._save_history = coerce_bool(obj=value, src_arg="save_history", src_obj=self)

    @property
    def certwarn(self) -> Optional[bool]:
        """Enable/disable SSL certificate warnings."""
        return self._proper("certwarn")

    @certwarn.setter
    def certwarn(self, value: Optional[T_CoerceBool]):
        self._certwarn = coerce_bool(
            obj=value, allow_none=True, allow_none_strs=True, src_arg="certwarn", src_obj=self
        )
        warn_toggle(self._certwarn, requests.urllib3.exceptions.InsecureRequestWarning)

    @property
    def timeout_connect(self) -> Optional[T_CoerceIntFloat]:
        """Timeout in seconds to wait for connection to open."""
        return self._proper("timeout_connect")

    @timeout_connect.setter
    def timeout_connect(self, value: Optional[T_CoerceIntFloat]):
        self._connect_timeout = coerce_int_float(
            value=value, min_value=0, allow_none=True, src_arg="timeout_connect", src_obj=self
        )

    @property
    def timeout_response(self) -> Optional[T_CoerceIntFloat]:
        """Timeout in seconds to wait for a response after connection is open."""
        return self._proper("timeout_response")

    @timeout_response.setter
    def timeout_response(self, value: Optional[T_CoerceIntFloat]):
        self._response_timeout = coerce_int_float(
            value=value, min_value=0, allow_none=True, src_arg="timeout_response", src_obj=self
        )

    @property
    def log_request_body(self) -> bool:
        """Log request bodies."""
        return self._proper("log_request_body")

    @log_request_body.setter
    def log_request_body(self, value: T_CoerceBool):
        """Pass."""
        self._log_request_body = coerce_bool(obj=value, src_arg="log_request_body", src_obj=self)

    @property
    def log_response_body(self) -> bool:
        """Log response bodies."""
        return self._proper("log_response_body")

    @log_response_body.setter
    def log_response_body(self, value: T_CoerceBool):
        """Pass."""
        self._log_response_body = coerce_bool(obj=value, src_arg="log_response_body", src_obj=self)

    @property
    def log_body_lines(self) -> int:
        """Maximum lines to log when logging request or response bodies."""
        return self._proper("log_body_lines")

    @log_body_lines.setter
    def log_body_lines(self, value: T_CoerceInt):
        self._log_body_lines = coerce_int(obj=value, src_arg="log_body_lines", src_obj=self)

    @property
    def log_level_http(self) -> str:
        """Log level assigned to :attr:`LOG`."""
        return self._proper("log_level_http")

    @log_level_http.setter
    def log_level_http(self, value: T_LogLevel):
        self._log_level_http = set_get_log_level(obj=self.LOG, level=value)

    @property
    def log_level_urllib(self) -> str:
        """Log level assigned to urllib's logger."""
        return self._proper("log_level_urllib")

    @log_level_urllib.setter
    def log_level_urllib(self, value: T_LogLevel):
        self._log_level_urllib = set_get_log_level(obj="urllib3.connectionpool", level=value)

    @property
    def log_level_request_attrs(self) -> str:
        """Log level used when logging request attrs."""
        return lowish(self._proper("log_level_request_attrs"))

    @log_level_request_attrs.setter
    def log_level_request_attrs(self, value: T_LogLevel):
        self._log_level_request_attrs = str_level(level=value)

    @property
    def log_level_request_body(self) -> str:
        """Log level used when logging request body."""
        return lowish(self._proper("log_level_request_body"))

    @log_level_request_body.setter
    def log_level_request_body(self, value: T_LogLevel):
        self._log_level_request_body = str_level(level=value)

    @property
    def log_level_response_attrs(self) -> str:
        """Log level used when logging response attrs."""
        return lowish(self._proper("log_level_response_attrs"))

    @log_level_response_attrs.setter
    def log_level_response_attrs(self, value: T_LogLevel):
        self._log_level_response_attrs = str_level(level=value)

    @property
    def log_level_response_body(self) -> str:
        """Log level used when logging response body."""
        return lowish(self._proper("log_level_response_body"))

    @log_level_response_body.setter
    def log_level_response_body(self, value: T_LogLevel):
        self._log_level_response_body = str_level(level=value)

    @property
    def log_request_attrs(self) -> str:
        """Request attributes that should be logged."""
        return self._get_log_attrs(attr_type="request")

    @log_request_attrs.setter
    def log_request_attrs(self, value: Union[str, List[str]]):
        self._set_log_attrs(attr_type="request", value=value)

    @property
    def log_response_attrs(self) -> str:
        """Response attributes that should be logged."""
        return self._get_log_attrs(attr_type="response")

    @log_response_attrs.setter
    def log_response_attrs(self, value: Union[str, List[str]]):
        self._set_log_attrs(attr_type="response", value=value)

    @property
    def env_url(self) -> str:
        """Value from OS Env AX_URL."""
        ret = self._env_values_http.get("url")
        return ret if is_str(ret) else ""

    @property
    def env_headers(self) -> dict:
        """Value from OS Env AX_HEADERS."""
        ret = self._env_values_http.get("headers")
        return ret if isinstance(ret, dict) else {}

    @property
    def env_cookies(self) -> dict:
        """Value from OS Env AX_COOKIES."""
        ret = self._env_values_http.get("cookies")
        return ret if isinstance(ret, dict) else {}

    @property
    def env_user_agent(self) -> str:
        """Value from OS Env AX_USER_AGENT."""
        ret = self._env_values_http.get("user_agent")
        return ret if is_str(ret) else ""

    def get_cert(self) -> cert_human.Cert:
        """Get the certificate offered by url."""
        response = self(verify=False)
        cert = response.raw.captured_cert
        source = {"url": self.url, "method": f"{self.get_cert}"}
        return cert_human.Cert(cert=cert, source=source)

    def get_cert_chain(self) -> List[cert_human.Cert]:
        """Get the full certificate chain offered by url."""
        response = self(verify=False)
        chain = response.raw.captured_chain or [response.raw.captured_cert]
        source = {"url": self.url, "method": f"{self.get_cert_chain}"}
        return [cert_human.Cert(cert=x, source=source) for x in chain]

    def _emit_request(self, value: T_Requests, **kwargs):
        """Log request and/or response bodies and/or attrs."""
        if isinstance(value, requests.PreparedRequest):
            case = "request"
            url = value.url
            body = value.body
            headers = value.headers
            cookies = value._cookies
        elif isinstance(value, requests.Response):
            case = "response"
            url = value.request.url
            body = value.text
            headers = value.headers
            cookies = value.cookies
        else:
            raise HttpError(f"Must be type {T_Requests}, not type {type(value)}: {value}")

        send_args = kwargs.get("send_args")
        value.size_human = cert_human.utils.human_len(body)
        value.clean_headers = self._hide(headers)
        value.clean_cookies = self._hide(cookies)
        value.send_args = send_args

        log_body = kwargs.get("log_body", getattr(self, f"log_{case}_body"))
        log_body = kwargs.get(f"log_{case}_body", log_body)
        log_hide_body = kwargs.get("log_hide_body", False)
        log_attrs = getattr(self, f"log_{case}_attrs")

        if log_attrs:
            level = kwargs.get(f"log_level_{case}_attrs", getattr(self, f"log_level_{case}_attrs"))
            msg = log_attrs.format(**{case: value})
            self._emit_log(msg=f"{case.upper()} ATTRS: {msg}", level=level)

        if log_body:
            if is_url_path_match(value=url, matches=self.log_hide_urls):
                log_hide_body = True

            level = kwargs.get("log_level_request_body", self.log_level_request_body)
            msg = json_log(
                obj=body,
                hide=log_hide_body,
                hidden=self.log_hide_str,
                trim=self.log_body_lines,
                matches=self.log_hide_matches,
            )
            self._emit_log(msg=f"{case.upper()} BODY: {msg}", level=level)

    def _emit_log(self, msg: str, level: str = "debug"):
        get_log_method(obj=self.LOG, method=level)(msg)

    def _hide(self, value: Any) -> Any:
        return hide_values(
            value=value, hidden=self.log_hide_str, matches=self.log_hide_matches, error=True
        )

    def _get_log_attrs(self, attr_type: str) -> str:
        """Get the log attributes for a specific type.

        Args:
            attr_type (str): 'request' or 'response'

        Returns:
            str: string template ready for .format
        """
        attr_map = getattr(AttrMaps, f"{attr_type}_map")
        attr = f"_log_{attr_type}_attrs"
        items = getattr(self, attr, [])
        ret = ""
        if items:
            ret = AttrMaps.join_pre + AttrMaps.join.join(
                [AttrMaps.tmpl.format(k=k, v=attr_map[k]) for k in items]
            )
        return ret

    def _set_log_attrs(self, attr_type: str, value: Union[str, List[str]]) -> List[str]:
        """Set the log attributes for a specific type.

        Args:
            attr_type: 'request' or 'response'
            value: user supplied attrs to log
        """
        attr_map = getattr(AttrMaps, f"{attr_type}_map")
        attrs = getattr(AttrMaps, f"{attr_type}_attrs")

        if isinstance(value, str):
            items = parse_csv_str(value=value)
        else:
            items = listify(items)

        items = [y for y in [x.lower().strip() for x in items] if y]
        attr = f"_log_{attr_type}_attrs"
        attr_value = []

        for idx, item in enumerate(items):
            if item in AttrMaps.wildcards:
                attr_value += [x for x in attr_map if x not in attr_value]
                break
            elif item not in attrs:
                raise HttpError(
                    f"Item {item} not a valid {attr_type} attribute"
                    f"\nItem #{idx + 1}/{len(items)} from value {value})"
                    f"\nValids: {attrs}"
                )
            else:
                if item not in attr_value:
                    attr_value.append(item)

        setattr(self, attr, attr_value)
        return attr_value

    def _parse_file(self, value: Optional[T_Pathy] = None) -> Optional[pathlib.Path]:
        """Pass."""
        ret = None
        if isinstance(value, T_Pathy) or is_str(value):
            ret, _ = path_read(obj=value, binary=True)
        return ret

    def _parse_url(self, value: Optional[T_Url] = None, **kwargs) -> Optional[str]:
        """Pass."""
        ret = None
        if isinstance(value, UrlParser):
            ret = value
        elif is_str(value):
            ret = UrlParser(url=value, **kwargs)
        return getattr(ret, "full_url", None)

    def _get_request_timeout(self, **kwargs) -> Tuple[Union[int, float], Union[int, float]]:
        """Pass."""
        timeout_connect = kwargs.get("timeout_connect", self.timeout_connect)
        timeout_response = kwargs.get("timeout_response", self.timeout_response)
        ret = kwargs.get("timeout", (timeout_connect, timeout_response))
        return ret

    def _get_request_proxies(self, **kwargs) -> dict:
        """Pass."""
        proxies = kwargs.get("proxies")
        proxy_http = kwargs.get("proxy_http", self.proxy_http)
        proxy_https = kwargs.get("proxy_https", self.proxy_https)

        ret = proxies if isinstance(proxies, dict) else {}
        ret.setdefault("http", proxy_http)
        ret.setdefault("https", proxy_https)
        return ret

    def _get_request_headers(self, **kwargs) -> CaseInsensitiveDict:
        """Headers to include in each request."""
        user_agent = kwargs.get("user_agent", self.user_agent)
        use_headers = kwargs.get("use_headers", True)
        use_headers_auth = kwargs.get("use_headers_auth", True)
        headers = kwargs.get("headers")

        ret = CaseInsensitiveDict()
        if use_headers:
            ret.update(self.env_headers if self.use_env_headers else {})
            ret.update(self.headers)

        if use_headers_auth:
            headers_auth = self.__get_headers_auth(**kwargs)
            ret.update(headers_auth if isinstance(headers_auth, T_Headers) else {})

        ret.update(headers if isinstance(headers, T_Headers) else {})
        ret.setdefault("User-Agent", user_agent)

        # XXX MOVE THIS TO ApiEndpoint
        ret.setdefault("Content-Type", "application/vnd.api+json")

        return ret

    def _get_request_cookies(self, **kwargs) -> RequestsCookieJar:
        """Cookies to include in each request."""
        cookies = kwargs.get("cookies")
        use_cookies = kwargs.get("use_cookies", True)

        ret = RequestsCookieJar()
        if use_cookies:
            ret.update(self.env_cookies if self.use_env_cookies else {})
            ret.update(self.cookies)
        ret.update(cookies if isinstance(cookies, T_Cookies) else {})
        return ret

    def _get_request_verify(self, **kwargs) -> Optional[Union[str, bool]]:
        """Value to use for each requests verify arg."""
        if "verify" in kwargs:
            return kwargs["verify"]
        ret = self.certverify
        if isinstance(self.certpath, pathlib.Path):  # XXX and is_file
            ret = str(self.certpath)
        return ret

    def _get_request_cert(self, **kwargs) -> Optional[Union[str, Tuple[str, str]]]:
        """Value to use for each requests cert arg."""
        if "cert" in kwargs:
            return kwargs["cert"]

        ret = None
        if self.cert_client_both:
            ret = f"{self.cert_client_both}"
        elif self.cert_client_key or self.cert_client_cert:  # XXX is_file!
            if self.cert_client_key and self.cert_client_cert:
                ret = (f"{self.cert_client_cert}", f"{self.cert_client_key}")
            else:
                raise HttpError(
                    "Must supply either ('cert_client_cert' AND 'cert_client_key') "
                    "OR 'cert_client_both'"
                )
        return ret

    @property
    def _env_values_http(self) -> dict:
        """Pass."""
        if not hasattr(self, "__ENV_VALUES_HTTP"):
            self.__ENV_VALUES_HTTP = get_env_values_http()
        return self.__ENV_VALUES_HTTP

    def _proper(self, prop: str) -> Any:
        if not hasattr(self, f"_{prop}"):
            super().__setattr__(f"_{prop}", getattr(self.VARS, prop))
        return getattr(self, f"_{prop}")

    @property
    def _objid(self) -> str:
        """Get cls module + name for logging."""
        return f"{self.__class__.__module__}.{self.__class__.__name__}"

    def _reset(self) -> requests.Session:
        """Reset the session object.

        Returns:
            requests.Session: newly created session object
        """
        if isinstance(self.session, requests.Session):
            self.LOG.debug("Creating new session")
            self.session.close()
            del self.session

        self.session = requests.Session()
        self.HISTORY = []
        self.LAST_REQUEST = None
        self.LAST_RESPONSE = None

        rcert = self._get_request_cert()
        rverify = self._get_request_verify()
        rtimeout = self._get_request_timeout()
        rproxies = self._get_request_proxies()
        rcookies = self._get_request_cookies()
        rheaders = self._get_request_headers(use_headers_auth=False)

        items = [
            f"url={self.url!r}",
            f"verify={rverify}",
            f"cert={rcert}",
            f"cookies={self._hide(rcookies)}",
            f"headers={self._hide(rheaders)}",
            f"proxies={rproxies}",
            f"timeout={rtimeout}",
        ]
        items = "\n  " + "\n  ".join(items)
        self.LOG.debug(f"New session created, per request args:{items}")
        return self.session

    def _send(self, *args, **kwargs):
        """Wrap of :meth:`requests.Session.send` for subclasses to play with."""
        return self.session.send(*args, **kwargs)

    def __get_headers_auth(self, **kwargs) -> Optional[CaseInsensitiveDict]:
        """Pass."""
        headers_auth = getattr(self, "__headers_auth", {})
        ret = CaseInsensitiveDict()
        ret.update(headers_auth if isinstance(headers_auth, T_Headers) else {})
        return ret

    def __setattr__(self, name, value):
        """Sauce to log property updates."""
        if isinstance(name, str) and name.startswith("_") and not name.startswith("__"):
            fname = name[1:]
            field = self.VARS.get_field(fname)
            if field:
                self.LOG.debug(
                    f"Updated property {fname!r} on {self._objid!r}"
                    f" from {self._hide(getattr(self, name, None))!r}"
                    f" to {self._hide(value)!r} field: {field}"
                )
        return super().__setattr__(name, value)

    def __str__(self) -> str:
        """Show object info."""
        items = [
            f"url={self.url!r}",
            f"user_agent={self.user_agent!r}",
            f"timeout_connect={self.timeout_connect}",
            f"timeout_response={self.timeout_response}",
        ]
        items = ", ".join(items)
        return f"{self._objid}({items})"

    def __repr__(self) -> str:
        """Show object info."""
        return self.__str__()
