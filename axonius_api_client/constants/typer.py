# -*- coding: utf-8 -*-
"""Custom types."""
import logging
import pathlib
from http import cookiejar as cookielib
from typing import List, Pattern, TypeVar, Union

import requests

T_Complex: TypeVar = Union[dict, list, tuple]
"""Complex JSON types."""

T_Simples: TypeVar = Union[str, int, bool, float]
"""Simple JSON types."""

T_StrListy: TypeVar = Union[str, List[str]]
"""Value will be coerced into a list, so can provide a str or list of strs."""

T_CoerceInt: TypeVar = Union[str, int]
"""Coercable int types."""

T_CoerceFloat: TypeVar = Union[float, int]
"""Coerceable float types."""

T_CoerceIntFloat: TypeVar = Union[str, int, float]
"""Coerceable int or float types."""

T_CoerceBool: TypeVar = Union[str, int, bool]
"""Coerceable boolean types."""

T_CoerceRe: TypeVar = Union[str, Pattern]
"""Value can be a str or regex pattern.

If value is str and starts with "~", will be converted into regex pattern.
"""

T_CoerceReListy: TypeVar = Union[T_CoerceRe, List[T_CoerceRe]]
"""Value can be a str or regex pattern, or list of str or regex pattern.

If value(s) are str and start with "~", will be converted into regex pattern.
"""

T_Json: TypeVar = Union[int, str, float, bool, dict, list, tuple, None]
"""Valid types for JSON."""

T_Cookies: TypeVar = Union[dict, cookielib.CookieJar]
"""Cookies accepted for :attr:`requests.session.cookies`."""

T_Headers: TypeVar = Union[dict, requests.structures.CaseInsensitiveDict]
"""Headers accepted for :attr:`requests.session.headers`."""

T_Verify: TypeVar = Union[bool, str]
"""Values accepted for :attr:`requests.session.verify`."""

T_LogLevel: TypeVar = Union[int, str]
"""Log level types accepted for coercion."""

T_LogObjs: TypeVar = Union[logging.Logger, logging.Handler]
"""Logger objects."""

T_LoggerStr: TypeVar = Union[logging.Logger, str]
"""Logger object or logger str."""

T_Pathy: TypeVar = Union[pathlib.Path, str]
"""Path like types accepted for coercion."""
