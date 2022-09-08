# -*- coding: utf-8 -*-
"""API for working with enforcements."""
import warnings
from typing import Generator, List, Optional, TypeVar, Union

from ...constants.api import MAX_PAGE_SIZE
from ...exceptions import ApiError, ApiWarning, NotFoundError
from ...parsers.tables import tablize
from ...tools import listify
from .. import json_api
from ..api_endpoints import ApiEndpoints
from ..assets.saved_query import T_Model as T_SavedQuery
from ..assets.saved_query import T_Multi as T_SavedQuery_Multi
from ..json_api.enforcements import (
    ActionCategory,
    QueryType,
    Schedule,
    SetBasic,
    SetDefaults,
    SetFull,
    UpdateResponse,
)
from ..mixins import ModelMixins

T_Basic: TypeVar = SetBasic
T_Full: TypeVar = SetFull
T_FullBasic: TypeVar = Union[T_Basic, T_Full]
T_Gen: TypeVar = Generator[T_FullBasic, None, None]
T_Multi: TypeVar = Union[str, dict, T_Basic, T_Full, UpdateResponse]
T_ActionType: TypeVar = json_api.enforcements.ActionType
T_ActionType_Multi: TypeVar = Union[str, dict, T_ActionType]


class Enforcements(ModelMixins):
    """API working with enforcements.

    Whats the deal with BASIC vs FULL?

    The REST API exposes an endpoint to page through the enforcement sets, but the details
    about the actions and triggers configured are limited.

    In order to get the full details of the actions and triggers, one call must be made to
    fetch the FULL details of each enforcement set by UUID.

    To make things more fun, the FULL model is lacking details that are only provided by the BASIC
    model: triggers_last_triggered, triggers_times_triggered, updated_by, last_triggered,
    last_updated. Also the "human friendly" description of trigger schedule is only available from
    BASIC.

    We overcome this by getting the FULL object and attaching the BASIC object as FULL.BASIC,
    see :method:`attach_full_set`.

    TBD:
        get_tasks
    """

    def get_set(
        self, value: T_Multi, refetch: bool = True, cache: Optional[List[T_Full]] = None
    ) -> T_Full:
        """Get an enforcement set by name or UUID.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid

        Raises:
            ApiError: if invalid type supplied for value
            NotFoundError: if not found

        Returns:
            T_Full: enforcement set model
        """
        if isinstance(value, str):
            name = value
            uuid = value
        elif isinstance(value, (T_Basic, T_Full, UpdateResponse)):
            if not refetch and isinstance(value, T_Full):
                return value
            name = value.name
            uuid = value.uuid
        elif isinstance(value, dict) and value.get("name") and value.get("uuid"):
            name = value["name"]
            uuid = value["uuid"]
        else:
            raise ApiError(f"Unknown type {type(value)}, must be {T_Multi}")

        items = []
        if (
            isinstance(cache, list)
            and cache
            and all([isinstance(x, (T_Basic, T_Full, UpdateResponse)) for x in cache])
        ):
            data = cache
        else:
            data = self.get_sets_generator(full=True)

        for item in data:
            if name == item.name or uuid == item.uuid:
                return item
            items.append(item)

        raise NotFoundError(
            tablize(
                value=[x.to_tablize() for x in items],
                err=f"Enforcement Set with name of {name!r} or UUID of {uuid!r} not found",
            )
        )

    def get_sets(
        self, generator: bool = False, full: bool = True
    ) -> Union[T_Gen, List[T_FullBasic]]:
        """Get all enforcement sets.

        Args:
            generator (bool, optional): return an iterator for objects
            full (bool, optional): get the full model of each enforcement set
        """
        gen = self.get_sets_generator(full=full)
        return gen if generator else list(gen)

    def get_sets_generator(self, full: bool = True) -> T_Gen:
        """Get all enforcement sets using a generator.

        Args:
            full (bool, optional): get the full model of each enforcement set

        Yields:
            T_Gen: Generator
        """
        offset = 0

        while True:
            rows = self._get_sets(offset=offset)
            offset += len(rows)

            if not rows:
                break

            for row in rows:
                yield self.attach_full_set(value=row) if full else row

    def attach_full_set(self, value: T_Basic) -> T_Full:
        """Fetch the full model of an enforcement set and attach the basic model to it.

        Args:
            value (T_Basic): Previously fetched basic model

        Returns:
            T_Full: Full model with basic model embedded

        Raises:
            ApiError: if value is incorrect type
        """
        if not isinstance(value, T_Basic):
            raise ApiError(f"Incorrect type {type(value)}, must be {T_Basic}")

        data = self._get_set(uuid=value.uuid)
        data.BASIC = value
        return data

    def check_set_exists(self, value: T_Multi):
        """Check if an enforcement set already exists.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid


        Raises:
            ApiError: if enforcement set already exists
        """
        try:
            existing = self.get_set(value=value)
        except NotFoundError:
            return

        raise ApiError(f"enforcement set matching {value!r} already exists:\n{existing}")

    def get_action_type(self, value: T_ActionType_Multi) -> T_ActionType:
        """Get an action type.

        Args:
            value (T_ActionType_Multi): action type model or str with name

        Returns:
            T_ActionType: action type model

        Raises:
            ApiError: if value is incorrect type
            NotFoundError: if not found
        """
        if isinstance(value, str):
            name = value
        elif isinstance(value, dict) and value.get("id"):
            name = value["id"]
        elif isinstance(value, T_ActionType):
            name = value.name
        else:
            raise ApiError(f"Unknown type {type(value)}, must be str, dict, or {T_ActionType}")

        items = self.get_action_types()

        for item in items:
            if item.name == name:
                return item

        raise NotFoundError(
            tablize(
                value=[x.to_tablize() for x in items],
                err=f"Action Type with name of {name!r} not found",
            )
        )

    def get_action_types(self) -> List[T_ActionType]:
        """Get all action types.

        Returns:
            List[T_ActionType]: action type models
        """
        return self._get_action_types()

    def copy(self, value: T_Multi, name: str, copy_triggers: bool = True) -> T_Full:
        """Copy an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            name (str): name to assign to copy
            copy_triggers (bool, optional): copy triggers to new set

        Returns:
            T_Full: copied enforcement set
        """
        existing = self.get_set(value=value)
        created = self._copy(uuid=existing.uuid, name=name, clone_triggers=copy_triggers)
        return self.get_set(value=created)

    def update_name(self, value: T_Multi, name: str) -> T_Full:
        """Update the name of an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            name (str): name to update

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        self.check_set_exists(value=name)
        existing.name = name
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_action_main(
        self, value: T_Multi, name: str, action_type: str, config: Optional[dict] = None
    ) -> T_Full:
        """Update the main action of an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            name (str): name to assign to action
            action_type (str): action type
            config (Optional[dict], optional): action configuration

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        action = self.get_set_action(name=name, action_type=action_type, config=config)
        existing.main_action = action
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_action_add(
        self,
        value: T_Multi,
        category: Union[ActionCategory, str],
        name: str,
        action_type: str,
        config: Optional[dict] = None,
    ) -> T_Full:
        """Add an action to an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            category (Union[ActionCategory, str]): action category to add action to
            name (str): name of action to add
            action_type (str): action type
            config (Optional[dict], optional): action configuration

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        action = self.get_set_action(name=name, action_type=action_type, config=config)
        existing.add_action(category=category, action=action)
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_action_remove(
        self, value: T_Multi, category: Union[ActionCategory, str], name: str
    ) -> T_Full:
        """Remove an action from an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            category (Union[ActionCategory, str]): action category to remove action from
            name (str): name of action to remove

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.remove_action(category=category, name=name)
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_query(
        self,
        value: T_Multi,
        query_name: str,
        query_type: Union[QueryType, str] = SetDefaults.query_type,
    ) -> T_Full:
        """Update the query of an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            query_name (str): name of saved query
            query_type (Union[QueryType, str], optional): type of saved query

        Returns:
            T_Full: updated enforcement set
        """
        sq = self.get_trigger_view(query_name=query_name, query_type=query_type)
        existing = self.get_set(value=value)
        existing.query_update(query_uuid=sq.uuid, query_type=query_type)
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_query_remove(self, value: T_Multi) -> T_Full:
        """Remove the query from an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.query_remove()
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_schedule_never(self, value: T_Multi) -> T_Full:
        """Set the schedule of an enforcement set to never run.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.set_schedule_never()
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_schedule_discovery(self, value: T_Multi) -> T_Full:
        """Set the schedule of an enforcement set to run every discovery.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.set_schedule_discovery()
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_schedule_hourly(self, value: T_Multi, recurrence: int) -> T_Full:
        """Set the schedule of an enforcement set to run hourly.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            recurrence (int): run schedule every N hours (N = 1-24)

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.set_schedule_hourly(recurrence=recurrence)
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_schedule_daily(
        self,
        value: T_Multi,
        recurrence: int,
        hour: int = SetDefaults.schedule_hour,
        minute: int = SetDefaults.schedule_minute,
    ) -> T_Full:
        """Set the schedule of an enforcement set to run daily.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            recurrence (int): run enforcement every N days (N = 1-~)
            hour (int, optional): hour of day to run schedule
            minute (int, optional): minute of hour to run schedule

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.set_schedule_daily(recurrence=recurrence, hour=hour, minute=minute)
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_schedule_weekly(
        self,
        value: T_Multi,
        recurrence: Union[str, List[Union[str, int]]],
        hour: int = SetDefaults.schedule_hour,
        minute: int = SetDefaults.schedule_minute,
    ) -> T_Full:
        """Set the schedule of an enforcement set to run weekly.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            recurrence (Union[str, List[Union[str, int]]]): run enforcement on days of week
            hour (int, optional): hour of day to run schedule
            minute (int, optional): minute of hour to run schedule

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.set_schedule_weekly(recurrence=recurrence, hour=hour, minute=minute)
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_schedule_monthly(
        self,
        value: T_Multi,
        recurrence: Union[str, List[Union[int, str]]],
        hour: int = SetDefaults.schedule_hour,
        minute: int = SetDefaults.schedule_minute,
    ) -> T_Full:
        """Set the schedule of an enforcement set to run monthly.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            recurrence (Union[str, List[int]]): run enforcement on days of month
            hour (int, optional): hour of day to run schedule
            minute (int, optional): minute of hour to run schedule

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.set_schedule_monthly(recurrence=recurrence, hour=hour, minute=minute)
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_only_new_assets(self, value: T_Multi, update: bool) -> T_Full:
        """Update enforcement set to only run against newly added assets from last automated run.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            update (bool): False=run against all assets each automated run, True=only run against
                newly added assets from last automated run

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.only_new_assets = update
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_on_count_increased(self, value: T_Multi, update: bool) -> T_Full:
        """Update enforcement set to only run if asset count increased from last automated run.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            update (bool): False=run regardless if asset count increased, True=only perform
                automated run if asset count increased

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.on_count_increased = update
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_on_count_decreased(self, value: T_Multi, update: bool) -> T_Full:
        """Update enforcement set to only run if asset count decreased from last automated run.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            update (bool): False=run regardless if asset count decreased, True=only perform
                automated run if asset count decreased

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.on_count_decreased = update
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_on_count_above(self, value: T_Multi, update: Optional[int]) -> T_Full:
        """Update enforcement set to only run automatically if asset count is above N.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            update (Optional[int]): None to always run automatically regardless of asset count,
                integer to only run automatically if asset count is above N

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.on_count_above = update
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_on_count_below(self, value: T_Multi, update: Optional[int]) -> T_Full:
        """Update enforcement set to only run automatically if asset count is below N.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid
            update (Optional[int]): None to always run automatically regardless of asset count,
                integer to only run automatically if asset count is below N

        Returns:
            T_Full: updated enforcement set
        """
        existing = self.get_set(value=value)
        existing.on_count_below = update
        updated = self.update_from_model(value=existing)
        return self.get_set(value=updated)

    def update_from_model(self, value: T_Full) -> T_Full:
        """Update an enforcement set from the values in a model.

        Args:
            value (T_Full): enforcement set model to update

        Returns:
            T_Full: updated enforcement set
        """
        return self._update(
            uuid=value.uuid, name=value.name, actions=value.actions, triggers=value.triggers
        )

    def create(
        self,
        name: str,
        main_action_name: str,
        main_action_type: str,
        main_action_config: Optional[dict] = None,
        query_name: Optional[str] = SetDefaults.query_name,
        query_type: str = SetDefaults.query_type,
        schedule_type: Union[Schedule, str] = SetDefaults.schedule_type,
        schedule_hour: int = SetDefaults.schedule_hour,
        schedule_minute: int = SetDefaults.schedule_minute,
        schedule_recurrence: Optional[Union[int, List[str]]] = SetDefaults.schedule_recurrence,
        only_new_assets: bool = SetDefaults.only_new_assets,
        on_count_above: Optional[int] = SetDefaults.on_count_above,
        on_count_below: Optional[int] = SetDefaults.on_count_below,
        on_count_increased: bool = SetDefaults.on_count_increased,
        on_count_decreased: bool = SetDefaults.on_count_decreased,
    ) -> T_Full:
        """Create an enforcement set.

        Args:
            name (str): Name to assign to enforcement set
            main_action_name (str): name to assign to main action
            main_action_type (str): action type to use for main action
            main_action_config (Optional[dict], optional): action config for main action
            query_name (Optional[str], optional): Saved Query name to use for trigger
            query_type (str, optional): Saved Query type
            schedule_type (Union[Schedule, str], optional): Schedule type for automation
            schedule_hour (int, optional): Hour of day to use for schedule_type
            schedule_minute (int, optional): Minute of hour to use for schedule_type
            schedule_recurrence (Optional[Union[int, List[str]]], optional): recurrence value,
                type changes based on schedule_type
            only_new_assets (bool, optional): only run set against assets added since last run
            on_count_above (Optional[int], optional): only run if asset count above N
            on_count_below (Optional[int], optional): only run if asset count below N
            on_count_increased (bool, optional): only run if asset count increased since last run
            on_count_decreased (bool, optional): only run if asset count decreased since last run

        Returns:
            T_Full: created enforcement set
        """
        self.check_set_exists(value=name)
        main = self.get_set_action(
            name=main_action_name, action_type=main_action_type, config=main_action_config
        )

        triggers = []
        sq = self.get_trigger_view(query_name=query_name, query_type=query_type)
        if sq:
            triggers.append(
                Schedule.get_trigger(
                    query_uuid=sq.uuid,
                    query_type=query_type,
                    schedule_type=schedule_type,
                    schedule_hour=schedule_hour,
                    schedule_minute=schedule_minute,
                    schedule_recurrence=schedule_recurrence,
                    only_new_assets=only_new_assets,
                    on_count_above=on_count_above,
                    on_count_below=on_count_below,
                    on_count_increased=on_count_increased,
                    on_count_decreased=on_count_decreased,
                )
            )

        created = self._create(name=name, main=main, triggers=triggers)
        return self.get_set(value=created)

    def delete(self, value: T_Multi) -> T_Full:
        """Delete an enforcement set.

        Args:
            value (T_Multi): enforcement set model or str with name or uuid

        Returns:
            T_Full: deleted enforcement set
        """
        obj = self.get_set(value=value)
        self._delete(uuid=obj.uuid)
        return obj

    def get_set_action(
        self,
        name: str,
        action_type: T_ActionType_Multi,
        config: Optional[dict] = None,
    ) -> dict:
        """Get the action dictionary needed to add an action to an enforcement set.

        Args:
            name (str): name to assign to action
            action_type (T_ActionType_Multi): action type to use
            config (Optional[dict], optional): action config

        Returns:
            dict: action dictionary
        """
        action_type = self.get_action_type(value=action_type)
        config = action_type.check_config(config=config)

        msg = (
            "CAUTION!!\n"
            "Adding an action with an incorrect configuration can result in"
            " an invalid Enforcement Set that can not be deleted!\n"
            "It is advised to create the appropriate action in the GUI to get an example"
        )
        warnings.warn(message=msg, category=ApiWarning)

        return T_Full.get_action_obj(name=name, action_type=action_type, config=config)

    def get_trigger_view(
        self,
        query_name: Optional[T_SavedQuery_Multi] = SetDefaults.query_name,
        query_type: Union[QueryType, str] = SetDefaults.query_type,
    ) -> Optional[T_SavedQuery]:
        """Get the saved query for use in adding a query to an enforcement.

        Args:
            query_name (Optional[T_SavedQuery_Multi], optional): Name of Saved Query
            query_type (Union[QueryType, str], optional): Type of Saved Query

        Returns:
            Optional[T_SavedQuery]: None if query_name is not supplied, otherwise saved query model
        """
        query_type = QueryType.get_value(query_type)

        if query_name is not None:
            return self._triggers_map[query_type.value].saved_query.get_by_multi(
                sq=query_name, as_dataclass=True
            )
        return None

    def _init(self, **kwargs):
        """Post init method for subclasses to use for extra setup."""
        from .. import Devices, Users, Instances, Vulnerabilities

        self.api_devices: Devices = Devices(auth=self.auth, **kwargs)
        """API model for cross reference."""

        self.api_users: Users = Users(auth=self.auth, **kwargs)
        """API model for cross reference."""

        self.api_vulnerabilities: Vulnerabilities = Vulnerabilities(auth=self.auth, **kwargs)
        """API model for cross reference."""

        self.api_instances: Instances = Instances(auth=self.auth, **kwargs)
        """API model for cross reference."""

    @property
    def _triggers_map(self) -> dict:
        """Map of query types to api objects."""
        return {
            QueryType.devices.value: self.api_devices,
            QueryType.users.value: self.api_users,
            QueryType.vulnerabilities.value: self.api_vulnerabilities,
        }

    def _delete(self, uuid: str) -> json_api.generic.Deleted:
        """Delete an enforcement set by UUID.

        Args:
            uuid (str): UUID of set to delete

        Returns:
            json_api.generic.Deleted: deleted model
        """
        api_endpoint = ApiEndpoints.enforcements.delete_set
        request_obj = api_endpoint.load_request(value={"ids": [uuid], "include": True})
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj)

    def _copy(self, uuid: str, name: str, clone_triggers: bool) -> T_Full:
        """Copy an enforcement set.

        Args:
            uuid (str): UUID of set to copy
            name (str): name to give copy
            clone_triggers (bool): copy triggers into new set

        Returns:
            T_Full: copied set
        """
        api_endpoint = ApiEndpoints.enforcements.copy_set
        request_obj = api_endpoint.load_request(
            id=uuid, uuid=uuid, name=name, clone_triggers=clone_triggers
        )
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj)

    def _update(
        self, uuid: str, name: str, actions: dict, triggers: Optional[List[dict]] = None
    ) -> T_Full:
        """Update an enforcement set.

        Args:
            uuid (str): UUID of set to update
            name (str): name of set
            actions (dict): actions of set
            triggers (Optional[List[dict]], optional): triggers of set

        Returns:
            T_Full: updated set
        """
        api_endpoint = ApiEndpoints.enforcements.update_set
        request_obj = api_endpoint.load_request(
            uuid=uuid, id=uuid, name=name, actions=actions, triggers=triggers or []
        )
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj, uuid=uuid)

    def _create(
        self,
        name: str,
        main: dict,
        success: Optional[List[dict]] = None,
        failure: Optional[List[dict]] = None,
        post: Optional[List[dict]] = None,
        triggers: Optional[List[dict]] = None,
    ) -> T_Full:
        """Create an enforcement set.

        Args:
            name (str): name of enforcement to create
            main (dict): main action
            success (Optional[List[dict]], optional): success actions
            failure (Optional[List[dict]], optional): failure actions
            post (Optional[List[dict]], optional): post actions
            triggers (Optional[List[dict]], optional): saved query trigger

        Returns:
            T_Full: created set
        """
        actions = {
            "main": main,
            "success": success or [],
            "failure": failure or [],
            "post": post or [],
        }
        api_endpoint = ApiEndpoints.enforcements.create_set
        request_obj = api_endpoint.load_request(name=name, actions=actions, triggers=triggers or [])
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj)

    def _get_sets(
        self,
        limit: int = MAX_PAGE_SIZE,
        offset: int = 0,
        sort: Optional[str] = None,
        filter: Optional[str] = None,
        search: str = "",
    ) -> List[T_Basic]:
        """Get enforcement sets in basic model.

        Args:
            limit (int, optional): limit to N rows per page
            offset (int, optional): start at row N
            sort (Optional[str], optional): sort based on a model attribute
            filter (Optional[str], optional): AQL filter
            search (str, optional): search string

        Returns:
            List[T_Basic]: basic models
        """
        api_endpoint = ApiEndpoints.enforcements.get_sets
        request_obj = api_endpoint.load_request(
            page={"limit": limit, "offset": offset}, filter=filter, search=search, sort=sort
        )
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj)

    def _get_set(self, uuid: str) -> T_Full:
        """Get an enforcement set in full model.

        Args:
            uuid (str): UUID of set to get

        Returns:
            T_Full: full model
        """
        api_endpoint = ApiEndpoints.enforcements.get_set
        return api_endpoint.perform_request(http=self.auth.http, uuid=uuid)

    def _get_action_types(self) -> List[T_ActionType]:
        """Get all action types.

        Returns:
            List[T_ActionType]: action type models
        """
        api_endpoint = ApiEndpoints.enforcements.get_action_types
        return api_endpoint.perform_request(http=self.auth.http)

    def _run_set_against_trigger(
        self, uuid: str, ec_page_run: bool = False, use_conditions: bool = False
    ) -> json_api.generic.Name:
        """Run an enforcement set against its trigger.

        Args:
            uuid (str): UUID of enforcement set to trigger
            ec_page_run (bool, optional): this was triggered from the EC Page
                in the GUI
            use_conditions (bool, optional): use conditions
                configured on enforcement set to determine execution

        """
        api_endpoint = ApiEndpoints.enforcements.run_set_against_trigger
        request_obj = api_endpoint.load_request(
            ec_page_run=ec_page_run, use_conditions=use_conditions
        )
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj, uuid=uuid)

    def _run_sets_against_trigger(
        self, uuids: List[str], include: bool = True, use_conditions: bool = False
    ) -> json_api.generic.ListDictValue:
        """Run enforcement sets against their triggers.

        Args:
            uuids (List[str]): UUIDs of enforcement sets to trigger
            include (bool, optional): select UUIDs in DB or UUIDs NOT in DB
            use_conditions (bool, optional): use conditions
                configured on enforcement set to determine execution

        """
        api_endpoint = ApiEndpoints.enforcements.run_sets_against_trigger
        value = {"ids": listify(uuids), "include": include}
        request_obj = api_endpoint.load_request(
            value=value,
            include=include,
            use_conditions=use_conditions,
        )
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj)

    def run(
        self, values: List[str], use_conditions: bool = False, error: bool = True
    ) -> List[T_Full]:
        """Run enforcement sets against their triggers.

        Args:
            values (List[str]): names or UUIDs of enforcement sets to trigger
            use_conditions (bool, optional): use conditions
                configured on enforcement set to determine execution
            error (bool, optional): throw error if an enforcement set has no trigger

        """
        cache = self.get_sets()
        items = [self.get_set(value=x, cache=cache) for x in listify(values)]
        to_run = []
        for item in items:
            if item.check_trigger_exists(msg="run enforcement set", error=error):
                to_run.append(item)

        if not to_run:
            raise ApiError(f"No enforcement sets with triggers found from values: {values!r}")

        names = [x.name for x in to_run]
        uuids = [x.uuid for x in to_run]
        if len(uuids) == 1:
            result = self._run_set_against_trigger(uuid=uuids[0], use_conditions=use_conditions)
        else:
            result = self._run_sets_against_trigger(uuids=uuids, use_conditions=use_conditions)

        finfo = f"with use_conditions={use_conditions}"
        self.LOG.info(f"Ran enforcement sets named {names} {finfo}\nResult: {result}")
        return to_run
