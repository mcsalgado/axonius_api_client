# -*- coding: utf-8 -*-
"""Python API Client for Axonius.

See Also:
    :obj:`client.Client` for creating a client for using this package.

"""
import logging

from . import setup_env, version

PACKAGE_ROOT: str = __package__
PACKAGE_FILE: str = __file__
VERSION: str = version.__version__
__version__ = VERSION

PACKAGE_LOG: logging.Logger = logging.getLogger(PACKAGE_ROOT)
"""root logger used by entire package, named after package."""

DEFAULT_PATH: str = setup_env.DEFAULT_PATH
"""default path to use throughout the package."""

load_dotenv = setup_env.load_dotenv
get_env_client = setup_env.get_env_client
get_env_connect = get_env_client

PRE_DOTENV: dict = setup_env.get_env_ax()
"""AX.* env variables before loading dotenv."""

INIT_DOTENV: str = load_dotenv()
"""Initial path to .env file that was loaded"""

POST_DOTENV: dict = setup_env.get_env_ax()
"""AX.* env variables after loading dotenv."""

try:
    from . import (
        api,
        cert_human,
        cli,
        constants,
        data,
        exceptions,
        http,
        logs,
        tools,
        connect,
        client,
    )
    from .api import (
        ActivityLogs,
        Adapters,
        ApiEndpoints,
        Cnx,
        Dashboard,
        Devices,
        Enforcements,
        Instances,
        Meta,
        RemoteSupport,
        SettingsGlobal,
        SettingsGui,
        SettingsLifecycle,
        Signup,
        SystemRoles,
        SystemUsers,
        Users,
        Wizard,
        WizardCsv,
        WizardText,
        Vulnerabilities,
    )
    from .connect import Connect, Client
    from .features import Features
    from .http import Http
except Exception:  # pragma: no cover
    raise


__all__ = (
    # API client
    "Connect",
    "Client",
    # HTTP client
    "Http",
    # API
    "Adapters",
    "Cnx",
    "Dashboard",
    "Devices",
    "Enforcements",
    "Instances",
    "Meta",
    "RemoteSupport",
    "SettingsGlobal",
    "SettingsGui",
    "SettingsLifecycle",
    "Signup",
    "SystemRoles",
    "SystemUsers",
    "Users",
    "Wizard",
    "Wizard",
    "WizardCsv",
    "WizardCsv",
    "WizardText",
    "WizardText",
    "ActivityLogs",
    "ApiEndpoints",
    "Features",
    "Vulnerabilities",
    # modules
    "api",
    "cli",
    "connect",
    "client",
    "constants",
    "data",
    "exceptions",
    "http",
    "logs",
    "tools",
    "version",
    "cert_human",
)
