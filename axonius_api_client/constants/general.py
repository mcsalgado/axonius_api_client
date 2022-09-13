# -*- coding: utf-8 -*-
"""Constants for general use."""
import calendar
import re
import sys
from typing import List, Pattern, Union

URL_STARTS: List[str] = ["https://", "http://"]

OK_ARGS: dict = {"fg": "green", "bold": True, "err": True}
"""default arguments for echo_ok"""

OK_TMPL: str = "** {msg}"
"""default template for echo_ok"""

DEBUG_ARGS: dict = {"fg": "blue", "bold": False, "err": True}
"""default arguments for echo_debug"""

DEBUG_TMPL: str = "** {msg}"
"""default template for echo_debug"""

WARN_ARGS: dict = {"fg": "yellow", "bold": True, "err": True}
"""default arguments for echo_warn"""

WARN_TMPL: str = "** WARNING: {msg}"
"""default template for echo_warn"""

ERROR_ARGS: dict = {"fg": "red", "bold": True, "err": True}
"""default arguments for echo_error"""

ERROR_TMPL: str = "** ERROR: {msg}"
"""default template for echo_error"""

PY36: bool = sys.version_info[0:2] >= (3, 6)
"""python version is 3.6 or higher"""

PY37: bool = sys.version_info[0:2] >= (3, 7)
"""python version is 3.7 or higher"""

EMPTY: List[Union[str, list, dict, tuple]] = [None, "", [], {}, ()]
"""Values that should be considered as empty"""

YES: List[Union[bool, int, str]] = [True, 1, "1", "true", "t", "yes", "y", "on"]
"""Values that should be considered as truthy"""

NO: List[Union[bool, int, str]] = [False, 0, "0", "false", "f", "no", "n", "off"]
"""Values that should be considered as falsey"""

IS_WINDOWS: bool = sys.platform == "win32"
"""Running on a windows platform"""

IS_LINUX: bool = sys.platform == "linux"
"""Running on a linux platform"""

IS_MAC: bool = sys.platform == "darwin"
"""Running on a mac platform"""

TRIM_MSG: str = "\nTrimmed {value_len} {trim_type} down to {trim}"
FILE_DATE_FMT: str = "%Y-%m-%dT%H-%M-%S"
NOT_SUPPLIED: str = "__NOT_SUPPLIED__"
EMAIL_RE_STR: str = (
    r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")"
    r"@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])"
)
EMAIL_RE: Pattern = re.compile(EMAIL_RE_STR, re.I)
DAYS_MAP: dict = dict(zip(range(7), calendar.day_name))
NONE_STRS: List[str] = ["none", "null", ""]
CSV_SPLIT: str = ","
KV_SPLIT: str = "="


TERMS: str = """Acceptance of Axonius Terms and Conditions.

I have read and agree to the Terms and Conditions and the Privacy Policy.

I understand and agree that any future purchase of a license to use an
Axonius Solution shall be governed by the Terms and Conditions and Privacy Policy as well.

Terms and Conditions: https://www.axonius.com/terms-conditions/
Privacy Policy: https://www.axonius.com/privacy-policy
"""
