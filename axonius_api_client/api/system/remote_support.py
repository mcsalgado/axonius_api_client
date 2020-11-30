# -*- coding: utf-8 -*-
"""API for working with product metadata."""
import dataclasses
import datetime
from typing import List, Optional

from ...data import BaseData
from ...tools import coerce_bool, coerce_int, dt_now, dt_parse, trim_float
from ..mixins import ModelMixins
from ..routers import API_VERSION, Router


@dataclasses.dataclass
class RemoteData(BaseData):
    """Pass."""

    raw: dict

    def __str__(self):
        """Pass."""
        return "\n".join(self.to_str_properties())

    def __repr__(self):
        """Pass."""
        return repr(self.__str__())

    @property
    def _properties(self):
        return [
            "last_modified",
            "enabled",
            "enabled_temporarily",
            "enabled_permanently",
            "temporary_expiry_date",
            "temporary_expires_in_hours",
            "analytics_enabled",
            "remote_access_enabled",
        ]

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

    @property
    def last_modified(self) -> datetime.datetime:
        """Pass."""
        return dt_parse(self.raw["_id"])

    @property
    def enabled_permanently(self) -> bool:
        """Pass."""
        return self.raw["provision"]

    @property
    def enabled_temporarily(self) -> bool:
        """Pass."""
        return bool(self.raw.get("timeout"))

    @property
    def enabled(self) -> bool:
        """Pass."""
        return self.enabled_permanently or self.enabled_temporarily

    @property
    def temporary_expiry_date(self) -> Optional[datetime.datetime]:
        """Pass."""
        value = self.raw.get("timeout")
        if value:
            return dt_parse(value)
        return None

    @property
    def temporary_expires_in_hours(self) -> Optional[float]:
        """Pass."""
        value = self.temporary_expiry_date
        if value:
            return trim_float((value - dt_now()).seconds / 60 / 60)
        return None

    @property
    def analytics_enabled(self) -> bool:
        """Pass."""
        return self.enabled and self.raw["analytics"]

    @property
    def remote_access_enabled(self) -> bool:
        """Pass."""
        return self.enabled and self.raw["troubleshooting"]


class RemoteSupport(ModelMixins):
    """API for working with configuring remote support system settings.

    Examples:
        NATCH

    """

    def get(self) -> RemoteData:
        """Pass."""
        return RemoteData(raw=self._get())

    def configure(self, enable: bool, temp_hours: Optional[int] = None) -> RemoteData:
        """Configure remote support.

        Args:
            enable: turn "Remote Support" on or off
            temp_hours: if enable is true, only enable for N hours

        """
        current_data = self.get()

        if enable:
            if temp_hours:
                hours = coerce_int(obj=temp_hours, min_value=1)

                self._update(data={"provision": False})
                self._start_temp(hours=hours)
                return self.get()

            if current_data.enabled_temporarily:
                self._stop_temp()

            self._update(data={"provision": True})
            return self.get()

        if current_data.enabled_temporarily:
            self._stop_temp()

        self._update(data={"provision": False})
        return self.get()

    def configure_features(self, analytics: bool, remote_access: bool) -> RemoteData:
        """Configure remote support features.

        Args:
            analytics: turn "Remote Support > Anonymized Analytics" on or off
            remote_access: turn "Remote Support > Remote Access" on or off

        """
        data = {
            "analytics": coerce_bool(obj=analytics),
            "troubleshooting": coerce_bool(obj=remote_access),
        }
        self._update(data=data)
        return self.get()

    def _get(self) -> dict:
        """Direct API method to get the properties for remote support."""
        path = self.router.remote_support
        return self.request(method="get", path=path)

    def _update(self, data: dict) -> dict:
        """Direct API method to update the properties for remote support."""
        path = self.router.remote_support
        return self.request(method="post", path=path, json=data)

    def _start_temp(self, hours: int) -> dict:
        """Direct API method to enable temporary remote support."""
        path = self.router.remote_support
        return self.request(method="put", path=path, json={"duration": hours})

    def _stop_temp(self) -> dict:
        """Direct API method to stop temporary remote support."""
        path = self.router.remote_support
        return self.request(method="delete", path=path)

    @property
    def router(self) -> Router:
        """Router for this API model."""
        return API_VERSION.system
