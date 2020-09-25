# -*- coding: utf-8 -*-
"""REST API route definitions."""
from typing import List

from ..tools import join_url


class Router:
    """Simple object store for REST API routes."""

    def __init__(self, object_type: str, base: str, version: int, **routes):
        """Object store for REST API routes.

        Args:
            object_type (:obj:`str`): object type for this set of routes
            base (:obj:`str`): base path for this set of routes
            version (:obj:`int`): api version for this set of routes
            **routes: routes for this object_type
        """
        self._version = version
        self._base = base
        self._object_type = object_type
        self.root = join_url(base, object_type)
        self._routes = ["root"]
        for k, v in routes.items():
            self._routes.append(k)
            items = [base, v] if v.startswith("/") else [self.root, v]
            setattr(self, k, join_url(*items))

    def __str__(self) -> str:
        """Show object info.

        Returns:
            :obj:`str`

        """
        msg = "{obj.__class__.__module__}.{obj.__class__.__name__}"
        msg += "(object_type={obj._object_type!r}, version={obj._version})"
        return msg.format(obj=self)

    def __repr__(self) -> str:
        """Show object info.

        Returns:
            :obj:`str`

        """
        return self.__str__()


class ApiV1:
    """Routes provided by the Axonius REST API version 1."""

    version: int = 1
    base: str = "api/V{version}".format(version=version)

    users: Router = Router(
        object_type="users",
        base=base,
        version=version,
        by_id="{id}",
        cached="cached",
        count="count",
        views="views",
        view_by_search_type="views/by-{search_type}/{value}",
        labels="labels",
        fields="fields",
        destroy="destroy",
        history_dates="history_dates",
    )

    devices: Router = Router(
        object_type="devices",
        base=base,
        cached="cached",
        version=version,
        by_id="{id}",
        count="count",
        views="views",
        view_by_search_type="views/by-{search_type}/{value}",
        labels="labels",
        fields="fields",
        destroy="destroy",
        history_dates="history_dates",
    )

    actions: Router = Router(
        object_type="actions",
        base=base,
        version=version,
        shell="shell",  # nosec
        deploy="deploy",
        upload_file="upload_file",
    )

    adapters: Router = Router(
        object_type="adapters",
        base=base,
        version=version,
        cnxs="{adapter_name_raw}/clients",
        cnxs_uuid="{adapter_name_raw}/clients/{cnx_uuid}",
        file_upload="{adapter_name_raw}/{adapter_node_id}/upload_file",
        # file_download="{name}/{node_id}/download_file",
        config_set="{adapter_name_raw}/{adapter_config_name}",
        config_get="{adapter_name_plugin}/{adapter_config_name}",
    )

    alerts: Router = Router(object_type="alerts", base=base, version=version)

    system: Router = Router(
        object_type="system",
        base=base,
        version=version,
        instances="instances",
        meta_about="meta/about",
        meta_historical_sizes="meta/historical_sizes",
        settings_lifecycle="settings/lifecycle",
        settings_gui="settings/gui",
        settings_core="settings/core",
        discover_lifecycle="discover/lifecycle",
        discover_start="discover/start",
        discover_stop="discover/stop",
        roles_default="roles/default",
        roles="roles",
        roles_by_uuid="roles/{uuid}",
        roles_labels="roles/labels",
        users="users",
        user="users/{uuid}",
        central_core="central_core",
        central_core_restore="central_core/restore",
    )

    all_objects: List[Router] = [
        users,
        devices,
        actions,
        adapters,
        alerts,
        system,
    ]


class ApiV4:
    """Routes provided by the Axonius REST API version 4.0."""

    version: float = 4.0
    base: str = "api/V{version}".format(version=version)

    users: Router = Router(
        object_type="users",
        base=base,
        version=version,
        by_id="{id}",
        cached="cached",
        count="count",
        views="views",
        view_by_search_type="views/by-{search_type}/{value}",
        labels="labels",
        fields="fields",
        destroy="destroy",
        history_dates="history_dates",
    )

    devices: Router = Router(
        object_type="devices",
        base=base,
        cached="cached",
        version=version,
        by_id="{id}",
        count="count",
        views="views",
        view_by_search_type="views/by-{search_type}/{value}",
        labels="labels",
        fields="fields",
        destroy="destroy",
        history_dates="history_dates",
    )

    actions: Router = Router(
        object_type="actions",
        base=base,
        version=version,
        shell="shell",  # nosec
        deploy="deploy",
        upload_file="upload_file",
    )

    adapters: Router = Router(
        object_type="adapters",
        base=base,
        version=version,
        cnxs="{adapter_name_raw}/connections",
        cnxs_test="{adapter_name_raw}/connections/test",
        cnxs_uuid="{adapter_name_raw}/connections/{cnx_uuid}",
        file_upload="{adapter_name_raw}/{adapter_node_id}/upload_file",
        # file_download="{name}/{node_id}/download_file",
        config_set="{adapter_name_raw}/{adapter_config_name}",
        config_get="{adapter_name_plugin}/{adapter_config_name}",
    )

    alerts: Router = Router(
        object_type="enforcements",
        base=base,
        version=version,
        upload_file="actions/upload_file",
    )

    instances: Router = Router(
        object_type="instances",
        base=base,
        version=version,
    )

    dashboard: Router = Router(
        object_type="dashboard",
        base=base,
        version=version,
        lifecycle="lifecycle",
    )

    system: Router = Router(
        object_type="settings",
        base=base,
        version=version,
        meta_about="meta/about",
        meta_historical_sizes="historical_sizes",
        settings_lifecycle="plugins/system_scheduler",
        settings_gui="plugins/gui",
        settings_core="plugins/core",
        discover_start="run_manual_discovery",
        discover_stop="stop_research_phase",
        roles_default="roles/default",
        roles="roles",
        roles_by_uuid="roles/{uuid}",
        roles_labels="roles/labels",
        users="users",
        user="users/{uuid}",
        central_core="central_core",
        central_core_restore="central_core/restore",
    )

    signup: Router = Router(
        object_type="signup",
        base=base,
        version=version,
    )

    labels: Router = Router(object_type="labels", base=base, version=version)

    all_objects: List[Router] = [
        users,
        devices,
        actions,
        adapters,
        alerts,
        instances,
        dashboard,
        system,
        labels,
        signup,
    ]


API_VERSION = ApiV4
