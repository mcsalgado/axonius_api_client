# -*- coding: utf-8 -*-
"""Base classes for data types."""
import copy
import dataclasses
import datetime
import enum
from typing import Any, Dict, List, Optional, Union

from .exceptions import ApiError


def factory_maker(value: Any, dup: bool = True, deep: bool = True) -> callable:
    """Pass."""

    def factory():
        return (copy.deepcopy(value) if deep else copy.copy(value)) if dup else value

    return factory


class BaseEnum(enum.Enum):
    """Base class for enums."""

    def _generate_next_value_(name, *args):
        """Get the next enum value in iterators."""
        return name

    def __str__(self):
        """Pass."""
        return str(self.value)

    @classmethod
    def get_value(cls, value: Union["BaseEnum", str]) -> "BaseEnum":
        """Pass."""
        if isinstance(value, cls):
            return value

        for item in cls:
            if value in [item.name, item.value]:
                return item

        valids = "\n" + "\n".join([repr(x) for x in cls])
        raise ApiError(f"Invalid {cls.__name__} value {value!r}, valids:{valids}")

    @classmethod
    def get_obj_by_value(
        cls,
        value: Any,
        match_name: bool = True,
        match_value: bool = True,
        match_obj: bool = True,
    ) -> "BaseEnum":
        """Pass."""
        for item in cls:
            if match_obj and item == value:
                return item
            if match_name and item.name == value:
                return item
            if match_value and item.value == value:
                return item

        valids = "\n" + "\n".join([repr(x) for x in cls])
        raise ApiError(f"Invalid {cls.__name__} value {value!r}, valids:{valids}")

    @classmethod
    def get_name_by_value(cls, value: Any, **kwargs) -> str:
        """Pass."""
        return cls.get_obj_by_value(value=value, **kwargs).name

    @classmethod
    def get_value_by_value(cls, value: Any, **kwargs) -> str:
        """Pass."""
        return cls.get_obj_by_value(value=value, **kwargs).value

    @classmethod
    def keys(cls) -> List[str]:
        """Pass."""
        return [x.name for x in cls]

    @classmethod
    def values(cls) -> List[str]:
        """Pass."""
        return [x.value for x in cls]

    @classmethod
    def to_dict(cls) -> dict:
        """Pass."""
        return {x.name: x.value for x in cls}


@dataclasses.dataclass
class BaseData:
    """Base class for dataclasses."""

    def to_dict(self) -> dict:
        """Get this dataclass object as a dictionary."""
        return dataclasses.asdict(self)

    def replace(self, **kwargs) -> "BaseData":  # pragma: no cover
        """Pass."""
        return dataclasses.replace(self, **kwargs)

    @staticmethod
    def _human_key(key):
        """Pass."""
        return key.replace("_", " ").title()

    @classmethod
    def get_fields(cls) -> List[dataclasses.Field]:
        """Get a list of fields defined for current this dataclass object."""
        return dataclasses.fields(cls)

    @classmethod
    def get_field_names(cls) -> List[str]:
        """Get a list of fields defined for current this dataclass object."""
        return list(cls.get_fields_dict())

    @classmethod
    def get_fields_dict(cls) -> Dict[str, dataclasses.Field]:
        """Pass."""
        return {x.name: x for x in cls.get_fields()}

    @classmethod
    def get_field(cls, name: str) -> Optional[dataclasses.Field]:
        """Pass."""
        return cls.get_fields_dict().get(name)


@dataclasses.dataclass
class PropsData(BaseData):
    """Pass."""

    raw: dict

    def __str__(self):
        """Pass."""
        return getattr(self, "_str_join", "\n").join(self.to_str_properties())

    def __repr__(self):  # pragma: no cover
        """Pass."""
        return repr(self.__str__())

    def to_str_properties(self) -> List[str]:
        """Pass."""
        return [f"{self._human_key(x)}: {getattr(self, x)}" for x in self._properties]

    def to_dict(self, dt_obj: bool = False) -> dict:
        """Pass."""

        def get_val(prop):
            value = getattr(self, prop)
            if not dt_obj and isinstance(value, datetime.datetime):
                return str(value)
            return value

        ret = {k: get_val(k) for k in self._properties}
        return ret
