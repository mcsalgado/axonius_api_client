# -*- coding: utf-8 -*-
"""Tools for getting OS env vars."""
import csv
import io
import logging
import os
import pathlib
from typing import Dict, List, Optional, Tuple, Union

import dotenv

LOGGER = logging.getLogger("axonius_api_client.setup_env")
"""Logger to use"""
dotenv.main.logger = LOGGER

KEY_PRE: str = "AX_"
"""Prefix for axonapi related OS env vars"""


class ENV_KEYS:
    """Pass."""

    DEFAULT_PATH: str = f"{KEY_PRE}PATH"
    """OS env to use for :attr:`DEFAULT_PATH` instead of CWD"""

    ENV_FILE: str = f"{KEY_PRE}ENV_FILE"
    """OS env to use for .env file name"""

    ENV_PATH: str = f"{KEY_PRE}ENV"
    """OS env to use for path to '.env' file"""

    OVERRIDE: str = f"{KEY_PRE}ENV_OVERRIDE"
    """OS env to control ignoring OS env when loading .env file"""

    URL: str = f"{KEY_PRE}URL"
    """OS env to get API URL from"""

    KEY: str = f"{KEY_PRE}KEY"
    """OS env to get API key from"""

    COOKIES: str = f"{KEY_PRE}COOKIES"
    """OS env to get CSV str of cookies from"""

    HEADERS: str = f"{KEY_PRE}HEADERS"
    """OS env to get CSV str of headers from"""

    SECRET: str = f"{KEY_PRE}SECRET"
    """OS env to get API secret from"""

    FEATURES: str = f"{KEY_PRE}FEATURES"
    """OS env to get API features to enable from"""

    CERTWARN: str = f"{KEY_PRE}CERTWARN"
    """OS env to get cert warning bool from"""

    CERTVERIFY: str = f"{KEY_PRE}CERTVERIFY"
    """OS env to get cert warning bool from"""

    CERTPATH: str = f"{KEY_PRE}CERTPATH"
    """OS env to get cert warning bool from"""

    DEBUG: str = f"{KEY_PRE}DEBUG"
    """OS env to enable debug logging"""

    DEBUG_PRINT: str = f"{KEY_PRE}DEBUG_PRINT"
    """OS env to use print() instead of LOGGER.debug()"""

    USER_AGENT: str = f"{KEY_PRE}USER_AGENT"
    """OS env to use a custom User Agent string."""

    BANNER: str = f"{KEY_PRE}BANNER"
    """OS env to show custom banner in Connect.__str__."""


CSV_SPLIT: str = ","
KV_SPLIT: str = "="

YES: List[str] = ["1", "true", "t", "yes", "y", "on"]
"""Values that should be considered as truthy"""

NO: List[str] = ["0", "false", "f", "no", "n", "off"]
"""Values that should be considered as falsey"""

DEFAULT_DEBUG: str = "no"
"""Default for :attr:`ENV_KEYS.DEBUG`"""

DEFAULT_DEBUG_PRINT: str = "no"
"""Default for :attr:`ENV_KEYS.DEBUG_PRINT`"""

DEFAULT_OVERRIDE: str = "yes"
"""Default for :attr:`ENV_KEYS.OVERRIDE`"""

DEFAULT_CERTWARN: str = "yes"
"""Default for :attr:`ENV_KEYS.CERTWARN`"""

DEFAULT_ENV_FILE: str = ".env"
"""Default for :attr:`ENV_KEYS.ENV_FILE`"""

KEYS_HIDDEN: List[str] = [ENV_KEYS.KEY, ENV_KEYS.SECRET, ENV_KEYS.USERNAME, ENV_KEYS.PASSWORD]
"""List of keys to hide in :meth:`get_env_ax`"""

HIDDEN: str = "_HIDDEN_"
"""Value to use for hidden keys in :meth:`get_env_ax`"""


def find_dotenv(
    ax_env: Optional[Union[str, pathlib.Path]] = None, default: str = os.getcwd()
) -> Tuple[str, str]:
    """Find a .env file.

    Args:
        ax_env: manual path to look for .env file
        default: default path to use if :attr:`KEY_DEFAULT_PATH` is not set

    Notes:
        Order of operations:

            * Check for ax_env for .env (or dir with .env in it)
            * Check for OS env var :attr:`KEY_ENV_PATH` for .env (or dir with .env in it)
            * Check for OS env var :attr:`KEY_DEFAULT_PATH` as dir with .env in it
            * use dotenv.find_dotenv() to walk tree from CWD
            * use dotenv.find_dotenv() to walk tree from package root
    """
    env_file = get_env_str(key=ENV_KEYS.ENV_FILE, default=DEFAULT_ENV_FILE)
    if ax_env:
        found_env = pathlib.Path(ax_env).expanduser().resolve()
        found_env = found_env / env_file if found_env.is_dir() else found_env
        if found_env.is_file():
            return "supplied", str(found_env)

    found_env = get_env_path(key=ENV_KEYS.ENV_PATH, get_dir=False)
    if found_env and found_env.exists():
        found_env = found_env / env_file if found_env.is_dir() else found_env
        if found_env.is_file():
            return "env_path", str(found_env)

    found_env = get_env_path(key=ENV_KEYS.DEFAULT_PATH, default=default)
    if found_env and found_env.exists():
        found_env = found_env / env_file if found_env.is_dir() else found_env
        if found_env.is_file():
            return "default_path", str(found_env)

    found_env = dotenv.find_dotenv(filename=env_file, usecwd=True) or ""
    if found_env and pathlib.Path(found_env).is_file():
        return "find_dotenv_cwd", found_env

    found_env = dotenv.find_dotenv(filename=env_file, usecwd=False) or ""
    if found_env and pathlib.Path(found_env).is_file():
        return "find_dotenv_pkg", found_env

    return "not_found", ""


def load_dotenv(ax_env: Optional[Union[str, pathlib.Path]] = None, **kwargs) -> str:
    """Load a '.env' file as environment variables accessible to this package.

    Args:
        ax_env: path to .env file to load, if directory will look for '.env' in that directory
        **kwargs: passed to dotenv.load_dotenv()
    """
    src, ax_env = find_dotenv(ax_env=ax_env)

    override = get_env_bool(key=ENV_KEYS.OVERRIDE, default=DEFAULT_OVERRIDE)
    DEBUG_LOG(f"Loading .env with override {override} from {src!r} {str(ax_env)!r}")
    if pathlib.Path(ax_env).is_file():
        DEBUG_LOG(f"{KEY_PRE}.* env vars before load dotenv: {get_env_ax()}")
        dotenv.load_dotenv(dotenv_path=ax_env, verbose=DEBUG, override=override)
        DEBUG_LOG(f"{KEY_PRE}.* env vars after load dotenv: {get_env_ax()}")
    return ax_env


def get_env_bool(key: str, default: Optional[bool] = None) -> bool:
    """Get an OS env var and turn convert it to a boolean.

    Args:
        key: OS env key
        default: default to use if not found

    Raises:
        :exc:`ValueError`: OS env var value is not able to be converted to bool
    """
    value = get_env_str(key=key, default=default, lower=True)
    if value in YES:
        return True

    if value in NO:
        return False

    msg = [
        f"Supplied value {value!r} for OS environment variable {key!r} must be one of:",
        f"  For true: {', '.join(YES)}",
        f"  For false: {', '.join(NO)}",
    ]
    raise ValueError("\n".join(msg))


def get_env_str(
    key: str, default: Optional[str] = None, empty_ok: bool = False, lower: bool = False
) -> str:
    """Get an OS env var.

    Args:
        key: OS env key
        default: default to use if not found
        empty_ok: dont throw an exc if the key's value is empty
        lower: lowercase the value

    Raises:
        :exc:`ValueError`: OS env var value is empty and empty_ok is False
    """
    orig_value = os.environ.get(key, "").strip()
    value = orig_value

    if default is not None and value in [None, ""]:
        value = default

    if not empty_ok and value in [None, ""]:
        raise ValueError(
            f"OS environment variable {key!r} is empty with value {orig_value!r}\n"
            f"Must specify {key!r} in .env file or in OS environment variable"
        )

    value = value.lower() if lower and isinstance(value, str) else value
    return value


def get_env_path(
    key: str, default: Optional[str] = None, get_dir: bool = True
) -> Union[pathlib.Path, str]:
    """Get a path from an OS env var.

    Args:
        key: OS env var to get path from
        default: default path to use if OS env var not set
        get_dir: return directory containing file of path is file
    """
    value = get_env_str(key=key, default=default, empty_ok=True)
    if value:
        value = pathlib.Path(value).expanduser().resolve()
        if get_dir and value.is_file():
            value = value.parent
    return value or ""


def get_env_csv(
    key: str,
    default: Optional[str] = None,
    empty_ok: bool = False,
    lower: bool = False,
    csv_split: str = CSV_SPLIT,
    strip_items: bool = True,
) -> List[str]:
    """Get an OS env var as a CSV.

    Args:
        key: OS env key
        default: default to use if not found
        empty_ok: dont throw an exc if the key's value is empty
        lower: lowercase the value
    """
    value = get_env_str(key=key, default=default, empty_ok=empty_ok, lower=lower)
    items = value.split(csv_split)
    if strip_items:
        return [y for y in [x.strip() for x in items] if y]
    return items


def parse_csv_kv_pairs(
    value: str,
    kv_split: str = KV_SPLIT,
    src: str = "",
) -> Dict[str, str]:
    """Pass."""
    rows = list(csv.reader(io.StringIO(value)))
    ret = {}
    for row_idx, row in enumerate(rows):
        row_info = f"row #{row_idx + 1}/{len(rows)} [{src}]"
        for item_idx, item in enumerate(row):
            if not item.strip():
                continue

            info = f"{row_info} item #{item_idx + 1}/{len(row)} {item!r} (from value {value!r})"

            if kv_split not in item:
                ikey, ivalue = item, None
            else:
                ikey, ivalue = item.split(kv_split, 1)

            ikey = ikey.strip()
            if not ikey.strip():
                raise ValueError(f"Empty key {ikey!r} found in {info}")

            ret[ikey] = ivalue
    return ret


def get_env_csv_kv_pairs(
    key: str,
    default: Optional[str] = None,
    empty_ok: bool = False,
    lower: bool = False,
    kv_split: str = KV_SPLIT,
) -> Dict[str, str]:
    """Get an OS env var as a CSV of key/value pairs.

    Examples:
        # good: AX_KEY="key1=value1,key2=value2"
        # bad: AX_KEY="key1=value1,=value2"

    Args:
        key: OS env key
        default: default to use if not found
        empty_ok: dont throw an exc if the key's value is empty
        lower: lowercase the value
    """
    value = get_env_str(key=key, default=default, empty_ok=empty_ok, lower=lower)
    src = f"from OS environment key {key!r}"
    ret = parse_csv_kv_pairs(value=value, kv_split=kv_split, src=src)
    return ret


def get_env_user_agent(**kwargs) -> str:
    """Pass."""
    _load(**kwargs)
    return get_env_str(key=ENV_KEYS.USER_AGENT, default="", empty_ok=True)


def get_env_cookies(**kwargs) -> Dict[str, str]:
    """Pass."""
    _load(**kwargs)
    return get_env_csv_kv_pairs(key=ENV_KEYS.COOKIES, default="", empty_ok=True)


def get_env_headers(**kwargs) -> Dict[str, str]:
    """Pass."""
    _load(**kwargs)
    return get_env_csv_kv_pairs(key=ENV_KEYS.HEADERS, default="", empty_ok=True)


def get_env_url(**kwargs) -> str:
    """Pass."""
    _load(**kwargs)
    return get_env_str(key=ENV_KEYS.URL, default="", empty_ok=True)


def get_env_key(**kwargs) -> str:
    """Pass."""
    _load(**kwargs)
    return get_env_str(key=ENV_KEYS.KEY, default="", empty_ok=True)


def get_env_secret(**kwargs) -> str:
    """Pass."""
    _load(**kwargs)
    return get_env_str(key=ENV_KEYS.SECRET, default="", empty_ok=True)


def get_env_certwarn(**kwargs) -> bool:
    """Pass."""
    _load(**kwargs)
    return get_env_bool(key=ENV_KEYS.CERTWARN, default=DEFAULT_CERTWARN)


def get_env_banner(**kwargs) -> str:
    """Pass."""
    _load(**kwargs)
    return get_env_str(key=ENV_KEYS.BANNER, default="", empty_ok=True)


def get_env_connect(load: bool = True, **kwargs) -> dict:
    """Get Connect arguments from OS env vars.

    Args:
        **kwargs: passed to :meth:`load_dotenv`
    """
    kwargs.setdefault("load", True)
    _load(**kwargs)
    return {
        "url": get_env_url(load=False),
        "key": get_env_key(load=False),
        "secret": get_env_secret(load=False),
        "certwarn": get_env_certwarn(load=False),
    }


def get_env_features(**kwargs) -> List[str]:
    """Get list of features to enable from OS env vars.

    Args:
        **kwargs: passed to :meth:`load_dotenv`
    """
    _load(**kwargs)
    value = get_env_csv(key=ENV_KEYS.FEATURES, default="", empty_ok=True, lower=True)
    return value


def _load(load: bool = False, **kwargs):
    """Pass."""
    if load:
        load_dotenv(**kwargs)


def get_env_ax(**kwargs):
    """Get all axonapi related OS env vars."""
    _load(**kwargs)
    value = {k: v for k, v in os.environ.items() if k.startswith(KEY_PRE)}
    value = {k: HIDDEN if k in KEYS_HIDDEN else v for k, v in value.items()}
    return value


def set_env(key: str, value: str, **kwargs) -> Tuple[str, Tuple[bool, str, str]]:
    """Set an environment variable in .env file."""
    from . import INIT_DOTENV as ax_env

    return dotenv.set_key(dotenv_path=ax_env, key_to_set=key, value_to_set=str(value))


DEBUG_PRINT: bool = get_env_bool(key=ENV_KEYS.DEBUG_PRINT, default=DEFAULT_DEBUG_PRINT)
"""Use print() instead of LOGGER.debug()."""

DEBUG_USE = print if DEBUG_PRINT else LOGGER.debug
"""use print or LOGGER.debug()"""

DEBUG: bool = get_env_bool(key=ENV_KEYS.DEBUG, default=DEFAULT_DEBUG)
"""Enable package wide debugging."""

DEBUG_LOG = DEBUG_USE if DEBUG else lambda x: x
"""Function to use for debug logging"""

DEFAULT_PATH: str = str(get_env_path(key=ENV_KEYS.DEFAULT_PATH, default=os.getcwd()))
"""Default path to use throughout this package"""
