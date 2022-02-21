# -*- coding: utf-8 -*-
"""Parent API for working with system settings."""
import pathlib
from typing import Optional, Union

from ...exceptions import ApiError, NotFoundError
from ...parsers.config import config_build, config_unchanged, config_unknown, parse_settings
from ...parsers.tables import tablize
from ...tools import path_read
from ..api_endpoints import ApiEndpoints
from ..json_api.generic import ApiBase, BoolValue
from ..json_api.system_settings import CertificateDetails, SystemSettings
from ..mixins import ModelMixins

STR_PATH = Union[str, pathlib.Path]
CONTENT = Union[str, bytes]


class SettingsMixins(ModelMixins):
    """Parent API for working with System Settings."""

    TITLE: str = ""
    """Title as shown in GUI for these settings."""

    PLUGIN_NAME: str = ""
    """Name of plugin for these settings."""

    CONFIG_NAME: str = ""
    """Name of config stored in :attr:`plugin` for these settings."""

    def get(self) -> dict:
        """Get the current system settings."""
        return parse_settings(raw=self._get().to_dict(), title=self.TITLE)

    def get_section(self, section: str, full_config: bool = False) -> dict:
        """Get the current settings for a section of system settings.

        Args:
            section: name of section
            full_config: return the full configuration
        """
        settings = self.get()
        title = settings["settings_title"]

        valid_sections = []

        for name, meta in settings["sections"].items():
            valid_sections.append(
                {
                    "Section Name": name,
                    "Section Title": meta["title"],
                    "Sub Section Names": "\n".join(list(meta["sub_sections"])),
                }
            )

            if name == section:
                if full_config:
                    meta["full_config"] = settings["config"]
                return meta

        err = f"Section Name {section!r} not found in {title}"
        raise NotFoundError(tablize(value=valid_sections, err=err))

    def get_sub_section(self, section: str, sub_section: str, full_config: bool = False) -> dict:
        """Get the current settings for a sub-section of a section of system settings.

        Args:
            section: name of section
            sub_section: name of sub section of section
            full_config: return the full configuration
        """
        settings = self.get_section(section=section, full_config=full_config)
        title = settings["settings_title"]

        if not settings["sub_sections"]:
            raise ApiError(f"Section Name {section!r} has no sub sections!")

        valids = []

        for name, meta in settings["sub_sections"].items():
            valids.append(
                {
                    "Sub Section Name": meta["name"],
                    "Sub Section Title": meta["title"],
                    "Section Name": meta["parent_name"],
                    "Section Title": meta["parent_title"],
                }
            )

            if name == sub_section:
                if full_config:
                    meta["full_config"] = settings["full_config"]
                return meta

        err = (
            f"Sub Section Name {sub_section!r} not found in under "
            f"Section Name {section!r} in {title}"
        )
        raise NotFoundError(tablize(value=valids, err=err))

    def update_section(self, section: str, check_unchanged: bool = True, **kwargs) -> dict:
        """Update the current settings for a section of system settings.

        Args:
            section: name of section
            **kwargs: settings to update
        """
        settings = self.get_section(section=section, full_config=True)
        title = settings["settings_title"]
        schemas = settings["schemas"]
        source = f"{title} Section Name {section!r}"
        old_config = settings["config"]
        full_config = settings["full_config"]

        new_config = {}
        new_config.update(kwargs)

        config_unknown(
            schemas=schemas,
            new_config=new_config,
            source=source,
        )
        config_build(
            schemas=schemas,
            old_config=old_config,
            new_config=new_config,
            source=source,
        )
        if check_unchanged:
            config_unchanged(
                schemas=schemas,
                old_config=old_config,
                new_config=new_config,
                source=source,
            )

        full_config[section] = new_config

        self._update(new_config=full_config)

        return self.get_section(section=section)

    def update_sub_section(self, section: str, sub_section: str, **kwargs) -> dict:
        """Update the current settings for a sub-section of a section of system settings.

        Args:
            section: name of section
            sub_section: name of sub section of section
            **kwargs: settings to update
        """
        settings = self.get_sub_section(section=section, sub_section=sub_section, full_config=True)
        title = settings["settings_title"]
        schemas = settings["schemas"]
        source = f"{title} Section Name {section!r} Sub Section Name {sub_section!r}"
        old_config = settings["config"]
        full_config = settings["full_config"]

        new_config = {}
        new_config.update(kwargs)

        config_unknown(
            schemas=schemas,
            new_config=new_config,
            source=source,
        )
        config_build(
            schemas=schemas,
            old_config=old_config,
            new_config=new_config,
            source=source,
        )
        config_unchanged(
            schemas=schemas,
            old_config=old_config,
            new_config=new_config,
            source=source,
        )

        full_config[section][sub_section] = new_config
        self._update(new_config=full_config)

        return self.get_sub_section(section=section, sub_section=sub_section)

    def file_upload(
        self,
        field_name: str,
        file_name: str,
        file_content: CONTENT,
        file_content_type: Optional[str] = None,
    ) -> ApiBase:
        """Pass."""
        return self._file_upload(
            file_name=file_name,
            field_name=field_name,
            file_content=file_content,
            file_content_type=file_content_type,
        )

    def file_upload_path(self, field_name: str, path: STR_PATH, **kwargs):
        """Pass."""
        path, file_content = path_read(obj=path, binary=True, is_json=False)
        if path.suffix == ".csv":
            kwargs.setdefault("file_content_type", "text/csv")
        kwargs.setdefault("file_name", path.name)
        kwargs["file_content"] = file_content
        return self.file_upload(field_name=field_name, **kwargs)

    def _file_upload(
        self,
        field_name: str,
        file_name: str,
        file_content: CONTENT,
        file_content_type: Optional[str] = None,
        file_headers: Optional[dict] = None,
    ) -> ApiBase:
        """Pass."""
        api_endpoint = ApiEndpoints.system_settings.file_upload

        data = {"field_name": field_name}
        files = {"userfile": (file_name, file_content, file_content_type, file_headers)}
        http_args = {"files": files, "data": data}

        response = api_endpoint.perform_request(
            http=self.auth.http, http_args=http_args, plugin=self.PLUGIN_NAME
        )
        response.filename = file_name
        return response

    def _get(self) -> SystemSettings:
        """Direct API method to get the current system settings."""
        api_endpoint = ApiEndpoints.system_settings.settings_get
        return api_endpoint.perform_request(
            http=self.auth.http, plugin_name=self.PLUGIN_NAME, config_name=self.CONFIG_NAME
        )

    def _update(self, new_config: dict) -> SystemSettings:
        """Direct API method to update the system settings.

        Args:
            new_config: new system settings to update
        """
        api_endpoint = ApiEndpoints.system_settings.settings_update
        request_obj = api_endpoint.load_request(
            config=new_config, configNmae=self.CONFIG_NAME, pluginId=self.PLUGIN_NAME
        )
        return api_endpoint.perform_request(
            http=self.auth.http,
            request_obj=request_obj,
            plugin_name=self.PLUGIN_NAME,
            config_name=self.CONFIG_NAME,
        )


class SettingsGlobal(SettingsMixins):
    """API for working with System Settings -> Global Settings."""

    TITLE: str = "Global Settings"
    """Title as shown in GUI for these settings."""

    PLUGIN_NAME: str = "core"
    """Name of plugin for these settings."""

    CONFIG_NAME: str = "CoreService"
    """Name of config stored in :attr:`plugin` for these settings."""

    def configure_destroy(self, enabled: bool, destroy: bool, reset: bool) -> dict:
        """Enable or disable destroy and factory reset API endpoints.

        Args:
            enabled: enable or disable destroy endpoints
            destroy: enable api/devices/destroy and api/users/destroy endpoints
            reset: enable api/factory_reset endpoint
        """
        return self.update_section(
            section="api_settings",
            enabled=enabled,
            enable_factory_reset=reset,
            enable_destroy=destroy,
            check_unchanged=False,
        )

    def cert_update_path(
        self, cert_file_path: STR_PATH, key_file_path: STR_PATH, **kwargs
    ) -> CertificateDetails:
        """Update the SSL cert in instance from cert & key files.

        Args:
            cert_file_path (STR_PATH): path to SSL certificate
            key_file_path (STR_PATH): path to SSL key
            **kwargs: passed to :meth:`cert_update`

        Returns:
            bool: if updating the SSL cert was successful
        """

        def load_file(path, key_base):
            file_path, file_contents = path_read(obj=cert_file_path, binary=True)
            kwargs[f"{key_base}_file_name"] = file_path.name
            kwargs[f"{key_base}_file_contents"] = file_contents

        load_file(path=cert_file_path, key_base="cert")
        load_file(path=key_file_path, key_base="key")

        return self.cert_update(**kwargs)

    def cert_get_details(self) -> CertificateDetails:
        """Get the details for the currently installed SSL cert.

        Returns:
            CertificateDetails: dataclass model with response from API
        """
        return self._cert_get_details()

    def cert_reset(self) -> CertificateDetails:
        """Get the details for the currently installed SSL cert.

        Returns:
            CertificateDetails: dataclass model with response from API
        """
        self._cert_reset()
        return self.cert_get_details()

    def cert_update(
        self,
        cert_file_contents: CONTENT,
        cert_file_name: str,
        key_file_contents: CONTENT,
        key_file_name: str,
        hostname: str,
        enabled: bool,
        passphrase: str = "",
    ) -> CertificateDetails:
        """Update the SSL cert in instance from cert & key strings.

        Args:
            cert_file_contents (CONTENT): Contents of SSL certificate
            cert_file_name (str): Name of file ``cert_file_contents`` came from
            key_file_contents (CONTENT): Contents of SSL Key
            key_file_name (str): Name of file ``key_file_contents`` came from
            hostname (str): value supplied as Common Name (CN) in cert
            enabled (bool): Enable SSL
            passphrase (str, optional): Passphrase for SSL Key, if one defined
        """
        cert_file = self._file_upload(
            field_name="cert_file",
            file_name=cert_file_name,
            file_content=cert_file_contents,
            file_content_type="application/x-x509-ca-cert",
        ).to_dict_file_spec()
        key_file = self._file_upload(
            field_name="private_key",
            file_name=key_file_name,
            file_content=key_file_contents,
            file_content_type="application/octet-stream",
        ).to_dict_file_spec()
        self._cert_update(
            hostname=hostname,
            passphrase=passphrase,
            enabled=enabled,
            cert_file=cert_file,
            private_key=key_file,
        )
        return self.cert_get_details()

    def _cert_update(self, **kwargs) -> bool:
        """Summary.

        Args:
            **kwargs: Passed to request object creation for this endpoint

        Returns:
            bool: Description
        """
        api_endpoint = ApiEndpoints.system_settings.cert_update
        request_obj = api_endpoint.load_request(**kwargs)
        return api_endpoint.perform_request(http=self.auth.http, request_obj=request_obj)

    def _cert_reset(self) -> BoolValue:
        """Summary.

        Returns:
            bool: Description
        """
        api_endpoint = ApiEndpoints.system_settings.cert_reset
        return api_endpoint.perform_request(http=self.auth.http)

    def _cert_get_details(self) -> CertificateDetails:
        """Get the details for the currently installed SSL cert.

        Returns:
            CertificateDetails: dataclass model with response from API
        """
        api_endpoint = ApiEndpoints.system_settings.cert_get_details
        return api_endpoint.perform_request(http=self.auth.http)


class SettingsGui(SettingsMixins):
    """API for working with System Settings -> GUI Settings."""

    TITLE: str = "GUI Settings"
    """Title as shown in GUI for these settings."""

    PLUGIN_NAME: str = "gui"
    """Name of plugin for these settings."""

    CONFIG_NAME: str = "GuiService"
    """Name of config stored in :attr:`plugin` for these settings."""


class SettingsIdentityProviders(SettingsMixins):
    """API for working with System Settings -> Identity Providers Settings."""

    TITLE: str = "Identity Providers Settings"
    """Title as shown in GUI for these settings."""

    PLUGIN_NAME: str = "gui"
    """Name of plugin for these settings."""

    CONFIG_NAME: str = "IdentityProviders"
    """Name of config stored in :attr:`plugin` for these settings."""


class SettingsLifecycle(SettingsMixins):
    """API for working with System Settings -> Lifecycle Settings."""

    TITLE: str = "Lifecycle Settings"
    """Title as shown in GUI for these settings."""

    PLUGIN_NAME: str = "system_scheduler"
    """Name of plugin for these settings."""

    CONFIG_NAME: str = "SystemSchedulerService"
    """Name of config stored in :attr:`plugin` for these settings."""
