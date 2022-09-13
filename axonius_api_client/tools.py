# -*- coding: utf-8 -*-
"""Utilities and tools."""
import codecs
import csv
import inspect
import io
import ipaddress
import json
import logging
import pathlib
import platform
import re
import sys
import warnings
from datetime import datetime, timedelta, timezone
from itertools import zip_longest
from types import GeneratorType
from typing import IO, Any, Dict, Iterable, Iterator, List, Optional, Tuple, Type, Union
from urllib.parse import urljoin, urlparse

import click
import dateutil.parser
import dateutil.relativedelta
import dateutil.tz

from . import INIT_DOTENV, PACKAGE_FILE, PACKAGE_ROOT, VERSION
from .constants.api import GUI_PAGE_SIZES
from .constants.general import (
    CSV_SPLIT,
    DAYS_MAP,
    DEBUG_ARGS,
    DEBUG_TMPL,
    EMAIL_RE,
    ERROR_ARGS,
    ERROR_TMPL,
    FILE_DATE_FMT,
    KV_SPLIT,
    NO,
    NONE_STRS,
    OK_ARGS,
    OK_TMPL,
    TRIM_MSG,
    URL_STARTS,
    WARN_ARGS,
    WARN_TMPL,
    YES,
)
from .constants.typer import T_CoerceRe, T_Pathy
from .exceptions import ToolsError
from .setup_env import find_dotenv, get_env_ax

LOG: logging.Logger = logging.getLogger(PACKAGE_ROOT).getChild("tools")


def path_repr(self):
    """Pass."""
    return f"{self.__str__()!r}"


pathlib.Path.__repr__ = path_repr


def listify(obj: Any, dictkeys: bool = False, consume: bool = False) -> list:
    """Force an object into a list.

    Notes:
        * :obj:`list`: returns as is
        * :obj:`tuple`: returns as list
        * :obj:`None`: returns as an empty list
        * :obj:`dict`: return as list of keys of obj if dictkeys is True, list with obj
            if False
        * generator: returns list if consume is True, generator if False
        * any thing else: returns as a list with obj as one item

    Args:
        obj: object to coerce to list
        dictkeys: if obj is dict, return list of keys of obj
        consume: if obj is generator, consume it
    """
    if isinstance(obj, GeneratorType):
        if consume:
            return list(obj)
        return obj

    if isinstance(obj, list):
        return obj

    if isinstance(obj, tuple):
        return list(obj)

    if obj is None:
        return []

    if isinstance(obj, dict) and dictkeys:
        return list(obj)

    return [obj]


def grouper(iterable: Iterable, n: int, fillvalue: Optional[Any] = None) -> Iterator:
    """Split an iterable into chunks.

    Args:
        iterable: iterable to split into chunks of size n
        n: length to split iterable into
        fillvalue: value to use as filler for last chunk
    """
    return zip_longest(*([iter(iterable)] * n), fillvalue=fillvalue)


def check_min_max_valid(
    value: Union[int, float, str],
    max_value: Optional[int] = None,
    min_value: Optional[int] = None,
    valid_values: Optional[List[int]] = None,
):
    """Pass."""
    errs = []
    if isinstance(value, (int, float)):
        if isinstance(max_value, (int, float)) and value > max_value:
            errs.append(f"Supplied value {value!r} is greater than max value of {max_value!r}.")

        if isinstance(min_value, (int, float)) and value < min_value:
            errs.append(f"Supplied value {value!r} is less than min value of {min_value!r}.")

    if isinstance(valid_values, (list, tuple)) and valid_values and value not in valid_values:
        errs.append(
            f"Supplied value {value!r} is not a valid value, valid values: {valid_values!r}."
        )
    return errs


def is_list(value: Any) -> bool:
    """Pass."""
    return isinstance(value, (list, tuple))


def coerce_re(
    value: Union[T_CoerceRe, List[T_CoerceRe]],
    convert_csv: bool = False,
    allow_none: bool = False,
    allow_none_strs: bool = False,
    none_strs: List[str] = NONE_STRS,
    error: bool = True,
) -> Optional[T_CoerceRe]:
    """Pass."""
    if convert_csv and isinstance(value, str):
        value = parse_csv_str(value=value)

    if is_list(value):
        ret = [
            coerce_re(
                value=x,
                allow_none=allow_none,
                allow_none_strs=allow_none_strs,
                none_strs=none_strs,
                error=error,
            )
            for x in value
        ]
        return [x for x in ret if isinstance(x, T_CoerceRe)]

    try:
        if isinstance(value, str) and value.startswith("~"):
            value = re.compile(value[1:], re.I)
        if not (isinstance(value, re.Pattern) or is_str(value)):
            raise TypeError(f"Value {value!r} must be type {T_CoerceRe}, not type {type(value)}")
    except Exception as exc:
        if error:
            raise ToolsError(f"Error coercing value to str or regex pattern: {exc}")
        value = None
    return value


def coerce_int(
    obj: Any,
    max_value: Optional[Union[int, float]] = None,
    min_value: Optional[Union[int, float]] = None,
    allow_none: bool = False,
    allow_none_strs: bool = False,
    none_strs: List[str] = NONE_STRS,
    valid_values: Optional[List[int]] = None,
    errmsg: Optional[str] = None,
    src_obj: Optional[object] = None,
    src_arg: Optional[str] = None,
) -> Optional[int]:
    """Convert an object into int.

    Args:
        obj: object to convert to int
        max_value: throw error if value is over this
        min_value: throw error if value is under this
        allow_none: if str of value lowered and stripped matches one of none_strs
        valid_values: throw error if value is not one of these values
        errmsg: optional error msg to show first
        src_obj: optional object using this tool
        src_arg: optional property using this tool

    Raises:
        :exc:`ToolsError`: if obj is not able to be converted to int
    """
    if check_none(
        value=obj, allow_none=allow_none, allow_none_strs=allow_none_strs, none_strs=none_strs
    ):
        return None

    errs = []

    try:
        obj = int(obj)
    except Exception:
        vtype = type(obj).__name__
        errs.append(f"Supplied value {obj!r} of type {vtype} is not an integer.")
    else:
        errs += check_min_max_valid(
            value=obj, min_value=min_value, max_value=max_value, valid_values=valid_values
        )

    if errs:
        raise ToolsError(
            "\n".join(build_err_msg(errmsg=errmsg, src_obj=src_obj, src_arg=src_arg, errs=errs))
        )
    return obj


def build_err_msg(errmsg=None, src_obj=None, src_arg=None, errs=None) -> List[str]:
    """Pass."""
    ret = []
    ret += listify(errmsg)
    if src_arg:
        ret.append(f"Error while handling argument {src_arg}")
    if src_obj:
        ret.append(f"Source object: {src_obj}")
    ret += listify(errs)
    return ret


def check_none(
    value: Any,
    allow_none: bool = False,
    allow_none_strs: bool = False,
    none_strs: List[str] = NONE_STRS,
) -> bool:
    """Pass."""
    return (allow_none and value is None) or (
        allow_none_strs and str(value).lower().strip() in listify(none_strs)
    )


def coerce_int_float(
    value: Union[int, float, str],
    max_value: Optional[int] = None,
    min_value: Optional[int] = None,
    valid_values: Optional[List[int]] = None,
    errmsg: Optional[str] = None,
    src_obj: Optional[object] = None,
    src_arg: Optional[str] = None,
    allow_none: bool = False,
    allow_none_strs: bool = False,
    none_strs: List[str] = NONE_STRS,
) -> Optional[Union[int, float]]:
    """Convert an object into int or float.

    Args:
        value: object to convert to int or float
        max_value: throw error if value is over this
        min_value: throw error if value is under this
        allow_none: if str of value lowered and stripped matches one of none_strs
        valid_values: throw error if value is not one of these values
        errmsg: optional error msg to show first
        src_obj: optional object using this tool
        src_arg: optional property using this tool

    Raises:
        :exc:`ToolsError`: if value is not able to be converted to int or float
    """
    if check_none(
        value=value, allow_none=allow_none, allow_none_strs=allow_none_strs, none_strs=none_strs
    ):
        return None

    if isinstance(value, str):
        value = value.strip()

        if "." in value and value.replace(".", "").isdigit():
            value = float(value)

        if value.isdigit():
            value = int(value)

    errs = []
    if not isinstance(value, (int, float)):
        vtype = type(value).__name__
        errs.append(f"Supplied value {value!r} of type {vtype} is not an integer or float.")
    else:
        errs += check_min_max_valid(
            value=value, min_value=min_value, max_value=max_value, valid_values=valid_values
        )

    if errs:
        raise ToolsError(
            "\n".join(build_err_msg(errmsg=errmsg, src_obj=src_obj, src_arg=src_arg, errs=errs))
        )
    return value


def coerce_bool(
    obj: Any,
    errmsg: Optional[str] = None,
    src_obj: Optional[object] = None,
    src_arg: Optional[str] = None,
    allow_none: bool = False,
    allow_none_strs: bool = False,
    none_strs: List[str] = NONE_STRS,
) -> bool:
    """Convert an object into bool.

    Args:
        obj: object to coerce to bool, will check against
            :data:`axonius_api_client.constants.general.YES` and
            :data:`axonius_api_client.constants.general.NO`

    Raises:
        :exc:`ToolsError`: obj is not able to be converted to bool
    """

    def combine(obj):
        return ", ".join([f"{x!r}" for x in obj])

    if check_none(
        value=obj, allow_none=allow_none, allow_none_strs=allow_none_strs, none_strs=none_strs
    ):
        return None

    if allow_none and (obj is None or str(obj).lower().strip() in none_strs):
        return None

    coerce_obj = obj

    if isinstance(obj, str):
        coerce_obj = coerce_obj.lower().strip()

    if coerce_obj in YES:
        return True

    if coerce_obj in NO:
        return False

    vtype = type(obj).__name__
    errs = [
        f"Supplied value {coerce_obj!r} of type {vtype} must be one of:",
        f"  For True: {combine(YES)}",
        f"  For False: {combine(NO)}",
    ]
    raise ToolsError(
        "\n".join(build_err_msg(errmsg=errmsg, src_obj=src_obj, src_arg=src_arg, errs=errs))
    )


def is_str(value: Any, not_empty: bool = True, strip=None) -> bool:
    """Check if value is non empty string."""
    if isinstance(value, str):
        if not_empty:
            return bool(value.strip(strip))
        return True
    return False


def check_is_strs(
    values: Any,
    src: str = "",
    parse_split: bool = False,
    split_on: str = ",",
    not_empty_list: bool = True,
    not_empty_str: bool = True,
) -> List[str]:
    """Check if a value is a list of non-empty strings."""

    def adderr(msg, idx):
        if msg not in errs:
            errs[msg] = []
        if isinstance(idx, int):
            errs[msg].append(idx)

    checks = listify(values)

    errs = {}
    if not_empty_list and not checks:
        adderr(msg="Empty list not allowed", idx=None)

    ret = []
    for idx, check in enumerate(checks):
        if isinstance(check, str):
            if not_empty_str and not check.strip():
                adderr(msg="Empty string", idx=idx)
                continue

            if parse_split:
                ret += [x.strip() for x in check.split(split_on) if x.strip()]
            else:
                ret.append(check)
        else:
            adderr(msg=f"Bad type {type(check)}", idx=idx)

    if errs:
        err_pre = f"Errors while checking supplied {src} {values!r} as a list of strings"
        msgs = "\n" + "\n".join([f"{k} at indexes: {v}" for k, v in errs.items()])
        raise ToolsError(f"{err_pre}:{msgs}")
    return ret


def is_email(value: Any) -> bool:
    """Check if a value is a valid email."""
    return is_str(value=value, not_empty=True) and bool(EMAIL_RE.fullmatch(value))


def is_int(obj: Any, digit: bool = False) -> bool:
    """Check if obj is int typeable.

    Args:
        obj: object to check
        digit: allow checking str/bytes
    """
    if digit:
        if (isinstance(obj, str) or isinstance(obj, bytes)) and obj.isdigit():
            return True

    return not isinstance(obj, bool) and isinstance(obj, int)


def join_url(url: str, *parts) -> str:
    """Join a URL to any number of parts.

    Args:
        url: str to add parts to
        *parts: str(s) to append to url
    """
    url = url.rstrip("/") + "/"
    for part in parts:
        if not part:
            continue
        url = url.rstrip("/") + "/"
        part = part.lstrip("/")
        url = urljoin(url, part)
    return url


def strip_right(obj: Union[List[str], str], fix: str) -> Union[List[str], str]:
    """Strip text from the right side of obj.

    Args:
        obj: str(s) to strip fix from
        fix: str to remove from obj(s)
    """
    if isinstance(obj, list) and all([isinstance(x, str) for x in obj]):
        return [strip_right(obj=x, fix=fix) for x in obj]

    if isinstance(obj, str):
        plen = len(fix)

        if obj.endswith(fix):
            return obj[:-plen]

    return obj


def strip_left(obj: Union[List[str], str], fix: str) -> Union[List[str], str]:
    """Strip text from the left side of obj.

    Args:
        obj: str(s) to strip fix from
        fix: str to remove from obj(s)
    """
    if isinstance(obj, list) and all([isinstance(x, str) for x in obj]):
        return [strip_left(obj=x, fix=fix) for x in obj]

    if isinstance(obj, str):
        plen = len(fix)

        if obj.startswith(fix):
            return obj[plen:]

    return obj


class AxJSONEncoder(json.JSONEncoder):
    """Pass."""

    def __init__(self, *args, **kwargs):
        """Pass."""
        self.fallback = kwargs.pop("fallback", None)
        super().__init__(*args, **kwargs)

    def default(self, obj):
        """Pass."""
        if isinstance(obj, datetime):
            return obj.isoformat()

        if has_to_dict(obj):
            return obj.to_dict()

        if callable(getattr(self, "fallback", None)):
            return self.fallback(obj)

        return super().default(obj)  # pragma: no cover


def has_to_dict(obj: Any) -> bool:
    """Pass."""
    return hasattr(obj, "to_dict") and callable(obj.to_dict)


def json_dump(
    obj: Any,
    indent: int = 2,
    sort_keys: bool = False,
    error: bool = True,
    fallback: Any = str,
    to_dict: bool = True,
    cls: Type = AxJSONEncoder,
    **kwargs,
) -> Any:
    """Serialize an object into json str.

    Args:
        obj: object to serialize into json str
        indent: json str indent level
        sort_keys: sort dict keys
        error: if json error happens, raise it
        **kwargs: passed to :func:`json.dumps`
    """
    obj = bytes_to_str(value=obj)

    if to_dict and has_to_dict(obj):
        obj = obj.to_dict()

    try:
        return json.dumps(
            obj, indent=indent, sort_keys=sort_keys, cls=cls, fallback=fallback, **kwargs
        )
    except Exception:  # pragma: no cover
        if error:
            raise
        return obj


def json_load(obj: str, error: bool = True, **kwargs) -> Any:
    """Deserialize a json str into an object.

    Args:
        obj: str to deserialize into obj
        error: if json error happens, raise it
        **kwargs: passed to :func:`json.loads`
    """
    try:
        return json.loads(obj, **kwargs)
    except Exception:
        if error:
            raise
        return obj


def json_reload(
    obj: Any,
    error: bool = False,
    trim: Optional[int] = None,
    trim_lines: bool = False,
    trim_msg: str = TRIM_MSG,
    **kwargs,
) -> str:
    """Re-serialize a json str into a pretty json str.

    Args:
        obj: str to deserialize into obj and serialize back to str
        error: If json error happens, raise it
        **kwargs: passed to :func:`json_dump`
    """
    obj = json_load(obj=obj, error=error)
    if not isinstance(obj, str):
        obj = json_dump(obj=obj, error=error, **kwargs)
    obj = coerce_str(value=obj, trim=trim, trim_msg=trim_msg, trim_lines=trim_lines)
    return obj


def dt_parse(obj: Union[str, timedelta, datetime], default_tz_utc: bool = False) -> datetime:
    """Parse a str, datetime, or timedelta into a datetime object.

    Notes:
        * :obj:`str`: will be parsed into datetime obj
        * :obj:`datetime.timedelta`: will be parsed into datetime obj as now - timedelta
        * :obj:`datetime.datetime`: will be re-parsed into datetime obj

    Args:
        obj: object or list of objects to parse into datetime
    """
    if isinstance(obj, list) and all([isinstance(x, str) for x in obj]):
        return [dt_parse(obj=x) for x in obj]

    if isinstance(obj, datetime):
        obj = str(obj)

    if isinstance(obj, timedelta):
        obj = str(dt_now() - obj)

    value = dateutil.parser.parse(obj)

    if default_tz_utc and not value.tzinfo:
        value = value.replace(tzinfo=dateutil.tz.tzutc())

    return value


def dt_parse_tmpl(obj: Union[str, timedelta, datetime], tmpl: str = "%Y-%m-%d") -> str:
    """Parse a string into the format used by the REST API.

    Args:
        obj: date time to parse using :meth:`dt_parse`
        tmpl: strftime template to convert obj into
    """
    valid_fmts = [
        "YYYY-MM-DD",
        "YYYYMMDD",
    ]
    try:
        dt = dt_parse(obj=obj)
        return dt.strftime(tmpl)
    except Exception:
        vtype = type(obj).__name__
        valid = "\n - " + "\n - ".join(valid_fmts)
        raise ToolsError(
            (
                f"Could not parse date {obj!r} of type {vtype}"
                f", try a string in the format of:{valid}"
            )
        )


def dt_now(
    delta: Optional[timedelta] = None,
    tz: timezone = dateutil.tz.tzutc(),
) -> datetime:
    """Get the current datetime in for a specific tz.

    Args:
        delta: convert delta into datetime str instead of returning now
        tz: timezone to return datetime in
    """
    if isinstance(delta, timedelta):
        return dt_parse(obj=delta)
    return datetime.now(tz)


def dt_now_file(fmt: str = FILE_DATE_FMT, **kwargs):
    """Pass."""
    return dt_now(**kwargs).strftime(fmt)


def dt_sec_ago(obj: Union[str, timedelta, datetime], exact: bool = False) -> int:
    """Get number of seconds ago a given datetime was.

    Args:
        obj: parsed by :meth:`dt_parse` into a datetime obj
    """
    obj = dt_parse(obj=obj)
    now = dt_now(tz=obj.tzinfo)
    value = (now - obj).total_seconds()
    return value if exact else round(value)


def dt_min_ago(obj: Union[str, timedelta, datetime]) -> int:
    """Get number of minutes ago a given datetime was.

    Args:
        obj: parsed by :meth:`dt_sec_ago` into seconds ago
    """
    return round(dt_sec_ago(obj=obj) / 60)


def dt_days_left(obj: Optional[Union[str, timedelta, datetime]]) -> Optional[int]:
    """Get number of days left until a given datetime.

    Args:
        obj: parsed by :meth:`dt_sec_ago` into days left
    """
    ret = None
    if obj:
        obj = dt_parse(obj=obj)
        now = dt_now(tz=obj.tzinfo)
        seconds = (obj - now).total_seconds()
        ret = round(seconds / 60 / 60 / 24)
    return ret


def dt_within_min(
    obj: Union[str, timedelta, datetime],
    n: Optional[Union[str, int]] = None,
) -> bool:
    """Check if given datetime is within the past n minutes.

    Args:
        obj: parsed by :meth:`dt_min_ago` into minutes ago
        n: int of :meth:`dt_min_ago` should be greater than or equal to
    """
    if not is_int(obj=n, digit=True):
        return False

    return dt_min_ago(obj=obj) >= int(n)


def get_path(obj: T_Pathy) -> pathlib.Path:
    """Convert a str into a fully resolved & expanded Path object.

    Args:
        obj: obj to convert into expanded and resolved absolute Path obj
    """
    return pathlib.Path(obj).expanduser().resolve()


def path_read(
    obj: T_Pathy, binary: bool = False, is_json: bool = False, **kwargs
) -> Union[bytes, str]:
    """Read data from a file.

    Notes:
        * if path filename ends with ".json", data will be deserialized using
          :meth:`json_load`

    Args:
        obj: path to read data form, parsed by :meth:`get_path`
        binary: read the data as binary instead of str
        is_json: deserialize data using :meth:`json_load`
        **kwargs: passed to :meth:`json_load`

    Raises:
        :exc:`ToolsError`: path does not exist as file
    """
    robj = get_path(obj=obj)

    if not robj.is_file():
        raise ToolsError(f"Supplied path='{obj}' (resolved='{robj}') does not exist!")

    if binary:
        data = robj.read_bytes()
    else:
        data = robj.read_text()

    if is_json:
        data = json_load(obj=data, **kwargs)

    if robj.suffix == ".json" and isinstance(data, str):
        kwargs.setdefault("error", False)
        data = json_load(obj=data, **kwargs)

    return robj, data


def get_backup_filename(path: T_Pathy) -> str:
    """Pass."""
    path = get_path(obj=path)
    return f"{path.stem}_{dt_now_file()}{path.suffix}"


def get_backup_path(path: T_Pathy) -> pathlib.Path:
    """Pass."""
    path = get_path(obj=path)
    return path.parent / get_backup_filename(path=path)


def check_path_is_not_dir(path: T_Pathy) -> pathlib.Path:
    """Pass."""
    path = get_path(obj=path)
    if path.is_dir():
        raise ToolsError(f"'{path}' is a directory, not a file")
    return path


def path_create_parent_dir(
    path: T_Pathy, make_parent: bool = True, protect_parent=0o700
) -> pathlib.Path:
    """Pass."""
    path = get_path(obj=path)

    if not path.parent.is_dir():
        if make_parent:
            path.parent.mkdir(mode=protect_parent, parents=True, exist_ok=True)
        else:
            raise ToolsError(
                f"Parent directory '{path.parent}' does not exist and make_parent is False"
            )
    return path


def path_backup_file(
    path: T_Pathy,
    backup_path: Optional[T_Pathy] = None,
    make_parent: bool = True,
    protect_parent=0o700,
    **kwargs,
) -> pathlib.Path:
    """Pass."""
    path = get_path(obj=path)
    if not path.is_file():
        raise ToolsError(f"'{path}' does not exist as a file, can not backup")

    if backup_path:
        backup_path = get_path(obj=backup_path)
    else:
        backup_path = get_backup_path(path=path)

    check_path_is_not_dir(path=backup_path)

    if backup_path.is_file():
        backup_path = get_backup_path(path=backup_path)

    path_create_parent_dir(path=backup_path, make_parent=make_parent, protect_parent=protect_parent)
    path.rename(backup_path)
    return backup_path


def auto_suffix(
    path: T_Pathy,
    data: Union[bytes, str],
    error: bool = False,
    **kwargs,
) -> Union[bytes, str]:
    """Pass."""
    path = get_path(obj=path)

    if path.suffix == ".json" and not (isinstance(data, str) or isinstance(data, bytes)):
        data = json_dump(obj=data, error=error, **kwargs)
    return data


def path_write(
    obj: T_Pathy,
    data: Union[bytes, str],
    overwrite: bool = False,
    backup: bool = False,
    backup_path: Optional[T_Pathy] = None,
    binary: bool = False,
    binary_encoding: str = "utf-8",
    is_json: bool = False,
    make_parent: bool = True,
    protect_file=0o600,
    protect_parent=0o700,
    suffix_auto: bool = True,
    **kwargs,
) -> Tuple[pathlib.Path, Tuple[int, Optional[pathlib.Path]]]:
    """Write data to a file.

    Notes:
        * if obj filename ends with ".json", serializes data using :meth:`json_dump`.

    Args:
        obj: path to write data to, parsed by :meth:`get_path`
        data: data to write to obj
        binary: write the data as binary instead of str
        binary_encoding: encoding to use when switching from str/bytes
        is_json: serialize data using :meth:`json_load`
        overwrite: overwrite obj if exists
        make_parent: If the parent directory does not exist, create it
        protect_file: octal mode of permissions to set on file
        protect_dir: octal mode of permissions to set on parent directory when creating
        **kwargs: passed to :meth:`json_dump`

    Raises:
        :exc:`ToolsError`: path exists as file and overwrite is False
        :exc:`ToolsError`: if parent path does not exist and make_parent is False
    """
    obj = get_path(obj=obj)

    if is_json:
        data = json_dump(**combo_dicts(kwargs, obj=data))

    if suffix_auto:
        data = auto_suffix(**combo_dicts(kwargs, path=obj, data=data))

    if binary:
        if isinstance(data, str):
            data = data.encode(binary_encoding)
        method = obj.write_bytes
    else:
        if isinstance(data, bytes):
            data = data.decode(binary_encoding)
        method = obj.write_text

    check_path_is_not_dir(path=obj)

    if obj.exists():
        if backup:
            backup_path = path_backup_file(
                path=obj,
                backup_path=backup_path,
                make_parent=make_parent,
                protect_parent=protect_parent,
            )
        elif overwrite is False:
            raise ToolsError(f"File '{obj}' already exists and overwrite is False")
    else:
        path_create_parent_dir(path=obj, make_parent=make_parent, protect_parent=protect_parent)

    obj.touch()

    if protect_file:
        obj.chmod(protect_file)

    bytes_written = method(data)
    return obj, (bytes_written, backup_path)


def longest_str(obj: List[str]) -> int:
    """Determine the length of the longest string in a list of strings.

    Args:
        obj: list of strings to calculate length of
    """
    return round(max([len(x) + 5 for x in obj]), -1)


def split_str(
    obj: Union[List[str], str],
    split: str = ",",
    strip: Optional[str] = None,
    do_strip: bool = True,
    lower: bool = True,
    empty: bool = False,
) -> List[str]:
    """Split a string or list of strings into a list of strings.

    Args:
        obj: string or list of strings to split
        split: character to split on
        strip: characters to strip
        do_strip: strip each item from the split
        lower: lowercase each item from the split
        empty: remove empty items post split
    """
    if obj is None:
        return []

    if isinstance(obj, list):
        return [
            y
            for x in obj
            for y in split_str(
                obj=x,
                split=split,
                strip=strip,
                do_strip=do_strip,
                lower=lower,
                empty=empty,
            )
        ]

    if not isinstance(obj, str):
        raise ToolsError(f"Unable to split non-str value {obj}")

    ret = []
    for x in obj.split(split):
        if lower:
            x = x.lower()
        if do_strip:
            x = x.strip(strip)
        if not empty and not x:
            continue
        ret.append(x)
    return ret


def echo_debug(msg: str, tmpl: bool = True, **kwargs):
    """Echo a message to console.

    Args:
        msg: message to echo
        tmpl: template to using for echo
        kwargs: passed to ``click.secho``
    """
    echoargs = {}
    echoargs.update(DEBUG_ARGS)
    echoargs.update(kwargs)
    if tmpl:
        msg = DEBUG_TMPL.format(msg=msg)

    LOG.debug(msg)
    click.secho(msg, **echoargs)


def echo_ok(msg: str, tmpl: bool = True, **kwargs):
    """Echo a message to console.

    Args:
        msg: message to echo
        tmpl: template to using for echo
        kwargs: passed to ``click.secho``
    """
    echoargs = {}
    echoargs.update(OK_ARGS)
    echoargs.update(kwargs)
    if tmpl:
        msg = OK_TMPL.format(msg=msg)

    LOG.info(msg)
    click.secho(msg, **echoargs)


def echo_warn(msg: str, tmpl: bool = True, **kwargs):
    """Echo a warning message to console.

    Args:
        msg: message to echo
        tmpl: template to using for echo
        kwargs: passed to ``click.secho``
    """
    echoargs = {}
    echoargs.update(WARN_ARGS)
    echoargs.update(kwargs)
    if tmpl:
        msg = WARN_TMPL.format(msg=msg)

    LOG.warning(msg)
    click.secho(msg, **echoargs)


def echo_error(msg: str, abort: bool = True, tmpl: bool = True, **kwargs):
    """Echo an error message to console.

    Args:
        msg: message to echo
        tmpl: template to using for echo
        kwargs: passed to ``click.secho``
        abort: call sys.exit(1) after echoing message
    """
    echoargs = {}
    echoargs.update(ERROR_ARGS)
    echoargs.update(kwargs)
    if tmpl:
        msg = ERROR_TMPL.format(msg=msg)

    LOG.error(msg)
    click.secho(msg, **echoargs)
    if abort:
        sys.exit(1)


def sysinfo() -> dict:
    """Gather system information."""
    try:
        cli_args = sys.argv
    except Exception:  # pragma: no cover
        cli_args = "No sys.argv!"

    info = {}
    info["API Client Version"] = VERSION
    info["API Client Package"] = PACKAGE_FILE
    info["Init loaded .env file"] = INIT_DOTENV
    info["Path to .env file"] = find_dotenv()
    info["OS envs"] = get_env_ax()
    info["Date"] = str(dt_now())
    info["Python System Version"] = ", ".join(sys.version.splitlines())
    info["Command Line Args"] = cli_args
    platform_attrs = [
        "machine",
        "node",
        "platform",
        "processor",
        "python_branch",
        "python_compiler",
        "python_implementation",
        "python_revision",
        "python_version",
        "release",
        "system",
        "version",
        "win32_edition",
    ]
    for attr in platform_attrs:
        method = getattr(platform, attr, None)
        value = "unavailable"
        if method:
            value = method()

        attr = attr.replace("_", " ").title()
        info[attr] = value
    return info


def calc_percent(part: Union[int, float], whole: Union[int, float], places: int = 2) -> float:
    """Calculate the percentage of part out of whole.

    Args:
        part: number to get percent of whole
        whole: number to caclulate against part
        places: number of decimal places to return
    """
    if 0 in [part, whole]:
        value = 0.00
    elif part > whole:
        value = 100.00
    else:
        value = 100 * (part / whole)

    value = trim_float(value=value, places=places)
    return value


def trim_float(value: float, places: int = 2) -> float:
    """Trim a float to N places.

    Args:
        value: float to trim
        places: decimal places to trim value to
    """
    if isinstance(places, int):
        value = float(f"{value:.{places}f}")
    return value


def join_kv(
    obj: Union[List[dict], dict], listjoin: str = ", ", tmpl: str = "{k}: {v!r}"
) -> List[str]:
    """Join a dictionary into key value strings.

    Args:
        obj: dict or list of dicts to stringify
        listjoin: string to use for joining
        tmpl: template to format key value pairs of dict
    """
    if isinstance(obj, list):
        return [join_kv(obj=x, listjoin=listjoin, tmpl=tmpl) for x in obj]

    if not isinstance(obj, dict):
        raise ToolsError(f"Object must be a dict, supplied {type(obj)}")

    items = []
    for k, v in obj.items():
        if isinstance(v, (list, tuple)):
            v = listjoin.join([str(i) for i in v])
            items.append(tmpl.format(k=k, v=v))
            continue

        if isinstance(v, dict):
            items.append(f"{k}:")
            items += join_kv(obj=v, listjoin=listjoin, tmpl="  " + tmpl)
            continue

        items.append(tmpl.format(k=k, v=v))

    return items


def get_type_str(obj: Any):
    """Get the type name of a class.

    Args:
        obj: class or tuple of classes to get type name(s) of
    """
    if isinstance(obj, tuple):
        return " or ".join([x.__name__ for x in obj])
    else:
        return obj.__name__


def check_type(value: Any, exp: Any, name: str = "", exp_items: Optional[Any] = None):
    """Check that a value is the appropriate type.

    Args:
        value: value to check type of
        exp: type(s) that value should be
        name: identifier of what value is for
        exp_items: if value is a list, type(s) that list items should be
    """
    name = f" for {name!r}" if name else ""

    if not isinstance(value, exp):
        vtype = get_type_str(obj=type(value))
        etype = get_type_str(obj=exp)
        err = f"Required type {etype}{name} but received type {vtype}: {value!r}"
        raise ToolsError(err)

    if exp_items and isinstance(value, list):
        for idx, item in enumerate(value):
            if isinstance(item, exp_items):
                continue
            vtype = get_type_str(obj=type(item))
            etype = get_type_str(obj=exp_items)
            err = (
                f"Required type {etype}{name} in list item {idx} but received "
                f"type {vtype}: {value!r}"
            )
            raise ToolsError(err)


def check_empty(value: Any, name: str = ""):
    """Check if a value is empty.

    Args:
        value: value to check type of
        name: identifier of what value is for
    """
    if not value:
        vtype = type(value).__name__
        name = f" for {name!r}" if name else ""
        err = f"Required value{name} but received an empty {vtype}: {value!r}"
        raise ToolsError(err)


def get_raw_version(value: str) -> str:
    """Caclulate the raw bits of a version str.

    Args:
        value: version to calculate
    """
    check_type(value=value, exp=str)
    converted = "0"
    version = value
    if ":" in value:
        if "." in value and value.index(":") > value.index("."):
            raise ToolsError(f"Invalid version with ':' after '.' in {value!r}")
        converted, version = value.split(":", 1)
    octects = version.split(".")
    for octect in octects:
        if not octect.isdigit():
            raise ToolsError(f"Invalid version with non-digit {octect!r} in {value!r}")
        if len(octect) > 8:
            octect = octect[:8]
        converted += "".join(["0" for _ in range(8 - len(octect))]) + octect
    return converted


def coerce_str_to_csv(
    value: str,
    coerce_list: bool = False,
    errmsg: Optional[str] = None,
) -> List[str]:
    """Coerce a string into a list of strings.

    Args:
        value: string to seperate using comma
    """
    pre = f"{errmsg}\n" if errmsg else ""

    new_value = value
    if isinstance(value, str):
        new_value = [x.strip() for x in value.split(",") if x.strip()]
        if not new_value:
            raise ToolsError(f"{pre}Empty value after parsing CSV: {value!r}")

    if not isinstance(new_value, (list, tuple)):
        if coerce_list:
            new_value = listify(obj=new_value)
        else:
            vtype = type(new_value).__name__
            raise ToolsError(f"{pre}Invalid type {vtype} supplied, must be a list")

    if not new_value:
        raise ToolsError(f"{pre}Empty list supplied {value}")

    return new_value


def parse_ip_address(value: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """Parse a string into an IP address.

    Args:
        value: ip address
    """
    try:
        return ipaddress.ip_address(value)
    except Exception as exc:
        raise ToolsError(str(exc))


def parse_ip_network(value: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    """Parse a string into an IP network.

    Args:
        value: ip network
    """
    if "/" not in str(value):
        vtype = type(value).__name__
        raise ToolsError(
            (
                f"Supplied value {value!r} of type {vtype} is not a valid subnet "
                "- format must be <address>/<CIDR>."
            )
        )
    try:
        return ipaddress.ip_network(value)
    except Exception as exc:
        raise ToolsError(str(exc))


def kv_dump(obj: dict) -> str:
    """Get a string representation of a dictionaries key value pairs.

    Args:
        obj: dictionary to get string of
    """
    return "\n  " + "\n  ".join([f"{k}: {v}" for k, v in obj.items()])


def bom_strip(content: Union[str, bytes], strip=True, bom: bytes = codecs.BOM_UTF8) -> str:
    """Remove the UTF-8 BOM marker from the beginning of a string.

    Args:
        content: string to remove BOM marker from if found
        strip: remove whitespace before & after removing BOM marker
    """
    content = content.strip() if strip else content

    if isinstance(bom, bytes) and isinstance(content, str):
        bom = bom.decode()
    elif isinstance(bom, str) and isinstance(content, bytes):
        bom = bom.encode()

    bom_len = len(bom)
    if content.startswith(bom):
        content = content[bom_len:]

    content = content.strip() if strip else content
    return content


def read_stream(stream) -> str:
    """Try to read input from a stream.

    Args:
        stream: stdin or a file descriptor to read input from
    """
    stream_name = format(getattr(stream, "name", stream))

    if stream.isatty():
        raise ToolsError(f"No input provided on {stream_name!r}")

    # its STDIN with input or a file
    content = stream.read().strip()

    if not content:
        raise ToolsError(f"Empty content supplied to {stream_name!r}")

    return content


def check_gui_page_size(size: Optional[int] = None) -> int:
    """Check page size to see if it one of the valid GUI page sizes.

    Args:
        size: page size to check

    Raises:
        :exc:`ApiError`: if size is not one of
            :data:`axonius_api_client.constants.api.GUI_PAGE_SIZES`

    """
    size = size or GUI_PAGE_SIZES[0]
    size = coerce_int(size)
    if size not in GUI_PAGE_SIZES:
        raise ToolsError(f"gui_page_size of {size} is invalid, must be one of {GUI_PAGE_SIZES}")
    return size


def calc_gb(value: Union[str, int], places: int = 2, is_kb: bool = True) -> float:
    """Convert bytes into GB.

    Args:
        value: bytes
        places: decimal places to trim value to
        is_kb: values are in kb or bytes
    """
    value = coerce_int_float(value=value)
    value = value / 1024 / 1024
    value = (value / 1024) if not is_kb else value
    value = trim_float(value=value, places=places)
    return value


def calc_perc_gb(
    obj: dict,
    whole_key: str,
    part_key: str,
    perc_key: Optional[str] = None,
    places: int = 2,
    update: bool = True,
    is_kb: bool = True,
) -> dict:
    """Calculate the GB and percent from a dict.

    Args:
        obj: dict to get whole_key and part_key from
        whole_key: key to get whole value from and convert to GB and set as whole_key_gb
        part_key: key to get part value from and convert to GB and set as part_key_gb
        perc_key: key to set percent in
        is_kb: values are in kb or bytes
    """
    perc_key = perc_key or f"{part_key}_percent"
    whole_value = obj[whole_key] or 0
    part_value = obj[part_key] or 0
    whole_gb = calc_gb(value=whole_value, places=places, is_kb=is_kb)
    part_gb = calc_gb(value=part_value, places=places, is_kb=is_kb)
    perc = calc_percent(part=part_gb, whole=whole_gb, places=places)
    ret = obj if update else {}
    ret[f"{part_key}_gb"] = part_gb
    ret[f"{whole_key}_gb"] = whole_gb
    ret[perc_key] = perc
    return ret


def get_subcls(cls: type, excludes: Optional[List[type]] = None) -> list:
    """Get all subclasses of a class."""
    excludes = excludes or []
    subs = [s for c in cls.__subclasses__() for s in get_subcls(c)]
    return [x for x in list(set(cls.__subclasses__()).union(subs)) if x not in excludes]


def prettify_obj(obj: Union[dict, list], indent: int = 0) -> List[str]:
    """Pass."""
    spaces = " " * indent
    sub_indent = indent + 2
    if isinstance(obj, dict):
        lines = ["", f"{spaces}-----"] if not indent else []
        for k, v in obj.items():
            lines += [f"{spaces}- {k}:", *prettify_obj(v, sub_indent)]
        return lines
    elif isinstance(obj, list):
        return [y for x in obj for y in prettify_obj(x, indent)]
    return [f"{spaces} {obj}"]


def token_parse(obj: str) -> str:
    """Pass."""
    url_check = "token="
    if isinstance(obj, str) and url_check in obj:
        idx = obj.index(url_check) + len(url_check)
        obj = obj[idx:]
    return obj


def combo_dicts(*args, **kwargs) -> dict:
    """Pass."""
    # TBD make this descend
    ret = {}
    for x in args:
        if isinstance(x, dict):
            ret.update(x)

    ret.update(kwargs)
    return ret


def is_url(value: str) -> bool:
    """Pass."""
    return isinstance(value, str) and any([value.startswith(x) for x in URL_STARTS])


def bytes_to_str(value: Any) -> Union[str, Any]:
    """Convert obj to str if it is bytes."""
    return value.decode() if isinstance(value, bytes) else value


def strip_str(value: Any) -> Union[str, Any]:
    """Strip a value if it is a string."""
    return value.strip() if isinstance(value, str) else value


def coerce_str(
    value: Any,
    strip: bool = True,
    none: Any = "",
    trim: Optional[int] = None,
    trim_lines: bool = False,
    trim_msg: str = TRIM_MSG,
) -> Union[str, Any]:
    """Coerce a value to a string."""
    value = bytes_to_str(value=value)
    if value is None:
        value = none

    if not isinstance(value, str):
        value = str(value)

    if strip:
        value = strip_str(value=value)

    value = str_trim(value=value, trim=trim, trim_lines=trim_lines, trim_msg=trim_msg)
    return value


def str_trim(
    value: str,
    trim: Optional[int] = None,
    trim_lines: bool = False,
    trim_msg: str = TRIM_MSG,
) -> str:
    """Pass."""
    trim_type = "lines" if trim_lines else "characters"

    if isinstance(trim, int) and trim > 0:
        trim_done = False
        if trim_lines:
            value = value.splitlines()
            value_len = len(value)
            if value_len >= trim:
                value = value[:trim]
                trim_done = True
            value = "\n".join(value)
        else:
            value_len = len(value)
            if value_len >= trim:
                value = value[:trim]
                trim_done = True

        if trim_done:
            value += trim_msg.format(trim_type=trim_type, trim=trim, value_len=value_len)
    return value


def get_cls_path(value: Any) -> str:
    """Pass."""
    if inspect.isclass(value):
        cls = value
    elif hasattr(value, "__class__"):
        cls = value.__class__
    else:
        cls = value

    if hasattr(cls, "__module__") and hasattr(cls, "__name__"):
        return f"{cls.__module__}.{cls.__name__}"

    return str(value)


def csv_writer(
    rows: List[dict],
    columns: Optional[List[str]] = None,
    quotes: str = "nonnumeric",
    dialect: str = "excel",
    line_ending: str = "\n",
    key_extra_error: bool = False,
    key_missing_value: Optional[Any] = None,
) -> str:  # pragma: no cover
    """Pass."""
    quotes = getattr(csv, f"QUOTE_{quotes.upper()}")
    if not columns:
        columns = []
        for row in rows:
            columns += [x for x in row if x not in columns]

    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=columns,
        quoting=quotes,
        lineterminator=line_ending,
        dialect=dialect,
        restval=key_missing_value,
        extrasaction="raise" if key_extra_error else "ignore",
    )
    writer.writerow(dict(zip(columns, columns)))
    writer.writerows(rows)
    content = stream.getvalue()
    stream.close()
    return content


def parse_int_min_max(value, default=0, min_value=None, max_value=None):
    """Pass."""
    if isinstance(value, str) and value.isdigit():
        value = int(value)

    if not isinstance(value, int):
        value = default

    if min_value is not None and value < min_value:
        value = default

    if max_value is not None and value > max_value:
        value = default

    return value


def safe_replace(obj: dict, value: str) -> str:
    """Pass."""
    for search, replace in obj.items():
        if isinstance(search, str) and isinstance(replace, str) and search and search in value:
            value = value.replace(search, replace)
    return value


def safe_format(
    value: T_Pathy, mapping: Optional[Dict[str, str]] = None, as_path: bool = False, **kwargs
) -> T_Pathy:
    """Pass."""
    is_path = isinstance(value, pathlib.Path)
    to_update = str(value) if is_path else value

    if not isinstance(to_update, str):
        return value

    for item in [mapping, kwargs]:
        if isinstance(item, dict) and item:
            to_update = safe_replace(obj=item, value=to_update)

    return get_path(to_update) if is_path or as_path else to_update


def get_paths_format(*args, mapping: Optional[Dict[str, str]] = None) -> Optional[pathlib.Path]:
    """Pass."""
    ret = None
    for path in args:
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        if isinstance(path, pathlib.Path):
            path = str(path)

        if isinstance(path, str):
            if isinstance(mapping, dict):
                path = safe_replace(obj=mapping, value=path)

            path = pathlib.Path(path)

        if isinstance(path, pathlib.Path):
            path = path.expanduser()

            if ret:
                ret = ret / path
            else:
                ret = path.resolve()
    return ret


def int_days_map(value: Union[str, List[Union[str, int]]], names: bool = False) -> List[str]:
    """Pass."""
    ret = []
    value = coerce_str_to_csv(value=value, coerce_list=True)
    valid = ", ".join([f"{v} ({k})" for k, v in DAYS_MAP.items()])

    for item in value:
        found = False
        for number, name in DAYS_MAP.items():
            if isinstance(item, str) and item.lower() == name.lower():
                ret.append(number)
                found = True

            if (isinstance(item, str) and item.isdigit()) or isinstance(item, int):
                item = coerce_int(
                    obj=item,
                    min_value=0,
                    max_value=6,
                    errmsg=f"Invalid day {item!r} supplied, valid: {valid}",
                )
                if item == number:
                    ret.append(number)
                    found = True

        if not found:
            item = str(item)
            raise ToolsError(f"Invalid day {item!r} supplied, valid: {valid}")

    if names:
        ret = [v for k, v in DAYS_MAP.items() if k in ret]
    else:
        ret = [str(k) for k, v in DAYS_MAP.items() if k in ret]

    return ret


def lowish(value: Any) -> Any:
    """Pass."""
    if isinstance(value, (list, tuple)):
        return [lowish(x) for x in value]
    return value.lower() if isinstance(value, str) else value


def is_tty(value: Any) -> bool:
    """Pass."""
    try:
        return value.isatty()
    except Exception:
        return False


def hide_value(
    key: Optional[Any] = None,
    value: Optional[Any] = None,
    hidden: Optional[str] = None,
    matches: Optional[List[T_CoerceRe]] = None,
    error: bool = True,
) -> Any:
    """Pass."""
    matches = coerce_re(value=listify(matches), allow_none=True, allow_none_strs=True, error=error)
    if isinstance(hidden, str) and matches:
        s_key = str(key)
        s_value = str(value)
        for match in matches:
            if (
                isinstance(match, re.Pattern) and (match.search(s_key) or match.search(s_value))
            ) or (match in [key, value, s_key, s_value]):
                return hidden

    return hide_values(value=value, hidden=hidden, matches=matches, error=error)


def hide_values(
    value: Any,
    hidden: Optional[str] = "",
    matches: Optional[List[T_CoerceRe]] = None,
    error: bool = True,
) -> Any:
    """Clean dict with sensitive information.

    Args:
        value (Any): dict to hide values of keys & values that match hide_values
        hidden (Optional[str], optional): str to use to hide values of keys/values
            that match matches
        matches (Optional[List[T_CoerceRe]], optional): strs or patterns to check
            against keys & values in value
        error (bool, optional): raise errors

    Returns:
        Any: cleaned value
    """
    matches = coerce_re(value=listify(matches), allow_none=True, allow_none_strs=True, error=error)
    if isinstance(hidden, str) and callable(getattr(value, "items", None)):
        try:
            return {
                k: hide_value(key=k, value=v, hidden=hidden, matches=matches)
                for k, v in value.items()
            }
        except Exception:
            return value
    return value


def parse_str_csv_kv_pairs(
    value: Optional[Union[str, IO]] = None,
    kv_split: str = KV_SPLIT,
    error: bool = True,
    csv_args: Optional[dict] = None,
    src: str = "",
    allow_none: bool = False,
    allow_none_strs: bool = False,
    none_strs: List[str] = NONE_STRS,
) -> dict:
    """Pass."""
    if check_none(
        value=value, allow_none=allow_none, allow_none_strs=allow_none_strs, none_strs=none_strs
    ):
        return {}
    fh = io.StringIO(value) if isinstance(value, str) else value
    return parse_str_csv_kv_pairs_fh(
        fh=fh, kv_split=kv_split, error=error, csv_args=csv_args, src=src
    )


def parse_csv_str(value: str, csv_split: str = CSV_SPLIT, strip: bool = True) -> List[str]:
    """Pass."""
    return [x.strip() if strip else x for x in value.split(csv_split) if x.strip()]


def parse_str_csv_kv_pairs_fh(
    fh: IO,
    kv_split: str = KV_SPLIT,
    csv_args: Optional[dict] = None,
    error: bool = True,
    src: str = "",
) -> dict:
    """Pass."""
    csv_args = csv_args if isinstance(csv_args, dict) else {}
    ret = {}

    try:
        rows = list(csv.reader(fh, **csv_args))
    except Exception as exc:
        raise ToolsError(f"Unable to parse CSV: {exc}")

    for row_idx, row in enumerate(rows):
        row_info = f"row #{row_idx + 1}/{len(rows)} [{src}]"
        for item_idx, item in enumerate(row):
            info = f"{row_info} item #{item_idx + 1}/{len(row)} {item!r}"
            try:
                if not item.strip():
                    LOG.debug(f"Empty item in {info}")
                    continue

                if kv_split not in item:
                    ikey, ivalue = item, None
                else:
                    ikey, ivalue = item.split(kv_split, 1)

                ikey = ikey.strip()
                if not ikey.strip():
                    msg = f"Empty key {ikey!r} found"
                    if error:
                        raise ValueError(msg)
                    LOG.error(msg)
                    continue

            except Exception as exc:
                msg = f"Error in {info}: {exc}"
                if error:
                    raise ToolsError(msg)
                LOG.error(msg)
                continue
            else:
                ret[ikey] = ivalue
        return ret


def clspath(value: object) -> str:
    """Pass."""
    return f"{value.__class__.__module}.{value.__class__.__name__}"


def warn_toggle(enable: Optional[bool] = False, *args, **kwargs) -> str:
    """Pass."""
    action = "default"
    if enable is True:
        action = "once"
    elif enable is False:
        action = "ignore"

    warnings.simplefilter(action, *args, **kwargs)
    return action


def get_path_fragments(value: str) -> List[str]:
    """Pass."""
    return [x for x in urlparse(value).path.strip("/").split("/") if x.strip()]


def is_url_path_match(
    value: str, matches: Optional[List[T_CoerceRe]] = None, error: bool = True
) -> bool:
    """Pass."""
    from ..tools import listify, coerce_re

    matches = coerce_re(value=listify(matches), allow_none=True, allow_none_strs=True, error=error)
    fragments = get_path_fragments(value)

    if any(isinstance(x, str) and x in fragments for x in matches):
        return True

    if any(isinstance(x, re.Pattern) and any(x.search(f) for f in fragments) for x in matches):
        return True
    return False


def json_log(
    obj: Any,
    hide: bool = False,
    hidden: Optional[str] = None,
    trim: Optional[int] = None,
    trim_msg: str = TRIM_MSG,
    matches: Optional[List[T_CoerceRe]] = None,
) -> str:
    """Pass."""
    ret = json_load(obj=obj, error=False)
    if hide and hasattr(ret, "items"):
        ret = hide_values(value=ret, hidden=hidden, matches=matches, error=False)
    ret = json_dump(obj=ret, error=False)
    return coerce_str(value=ret, trim=trim, trim_msg=trim_msg, trim_lines=True)
