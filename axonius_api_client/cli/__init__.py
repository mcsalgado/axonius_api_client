# -*- coding: utf-8 -*-
"""Command line interface for Axonius API Client."""
import sys

import click

from .. import version
from ..constants.http import VARS_CLI, VARS_CLIENT, AttrMaps
from ..constants.logs import LOG_LEVELS_STR
from ..logs import PACKAGE_LOG
from . import (
    context,
    grp_adapters,
    grp_assets,
    grp_certs,
    grp_enforcements,
    grp_openapi,
    grp_system,
    grp_tools,
)


PROTIPS: str = """
\b
Tips:
- All of the options listed above must be supplied BEFORE any commands or groups.
  - CORRECT: axonshell --log-console devices count
  - INCORRECT: axonshell devices count --log-console
- OS Environment variables:
  1) All values stored in .env files will be treated as OS environment variables.
  2) Use  AX_ENV to point to a custom .env file:
    - bash: export AX_ENV=/path/to/.env  # for all commands in current shell
    - bash: AX_ENV=/path/to/.env axonshell tools shell  # for single commands
    - cmd.exe: setenv AX_ENV c:\\path\\to\\.env
  3) Use AX_COOKIES and AX_HEADERS as comma seperated values:
    - key1=value1,key2=value2,key3=value4
  4) Use AX_URL, AX_KEY, AX_SECRET to specify credentials
"""


@click.group(cls=context.AliasedGroup, context_settings=context.CONTEXT_SETTINGS, epilog=PROTIPS)
@click.option(
    "--quiet/--no-quiet",
    "-q/-nq",
    "quiet",
    default=False,
    help="Silence green text.",
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--header",
    "headers",
    help="Additional headers to use in all requests in the format of key=value (multiples)",
    # let http client handle OS env
    allow_from_autoenv=False,
    show_default=False,
    multiple=True,
    type=context.SplitEquals(),
)
@click.option(
    "--cookie",
    "cookies",
    help="Additional cookies to use in all requests in the format of key=value (multiples)",
    # let http client handle OS env
    allow_from_autoenv=False,
    show_default=False,
    multiple=True,
    type=context.SplitEquals(),
)
@click.option(
    "--log-level-package",
    "-lvlpkg",
    "log_level_package",
    default=VARS_CLIENT.log_level_package,
    help="Logging level to use for entire package.",
    type=click.Choice(LOG_LEVELS_STR),
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-level-http",
    "-lvlhttp",
    "log_level_http",
    default=VARS_CLIENT.log_level_http,
    help="Logging level to use for http client.",
    type=click.Choice(LOG_LEVELS_STR),
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-level-api",
    "-lvlapi",
    "log_level_api",
    default=VARS_CLIENT.log_level_api,
    help="Logging level to use for api clients.",
    type=click.Choice(LOG_LEVELS_STR),
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-level-console",
    "-lvlcon",
    "log_level_console",
    default=VARS_CLIENT.log_level_console,
    help="Logging level to use for console output.",
    type=click.Choice(LOG_LEVELS_STR),
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-level-file",
    "-lvlfile",
    "log_level_file",
    default=VARS_CLIENT.log_level_file,
    help="Logging level to use for file output.",
    type=click.Choice(LOG_LEVELS_STR),
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-request-attrs",
    "-reqattr",
    "log_request_attrs",
    help=f"Log http client request attributes (CSV list of any of: {AttrMaps.request_attrs})",
    default=VARS_CLIENT.log_request_attrs,
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-response-attrs",
    "-respattr",
    "log_response_attrs",
    default=VARS_CLIENT.log_response_attrs,
    help="Log http client response attributes  (CSV list of any of: {AttrMaps.response_attrs})",
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-request-body",
    "-reqbody",
    "log_request_body",
    default=VARS_CLIENT.log_request_body,
    help="Log http client request body.",
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--log-response-body",
    "-respbody",
    "log_response_body",
    help="Log http client response body.",
    default=VARS_CLIENT.log_response_body,
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--log-console/--no-log-console",
    "-c/-nc",
    "log_console",
    default=VARS_CLIENT.log_console,
    help="Enable logging to STDERR.",
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--log-file/--no-log-file",
    "-f/-nf",
    "log_file",
    default=VARS_CLIENT.log_file,
    help="Enable logging to -fn/--log-file-name in -fp/--log-file-path.",
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--log-file-rotate/--no-log-file-rotate",
    "-fr/-nfr",
    "log_file_rotate",
    default=VARS_CLI.log_file_rotate,
    help="Force the log file to rotate.",
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--log-file-name",
    "-fn",
    "log_file_name",
    metavar="FILENAME",
    default=VARS_CLIENT.log_file_name,
    help="Log file to save logs to if -f/--log-file supplied.",
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-file-path",
    "-fp",
    "log_file_path",
    metavar="PATH",
    default=VARS_CLIENT.log_file_path,
    help="Directory to use for -fn/--log-file-name (Defaults to current directory).",
    show_envvar=True,
)
@click.option(
    "--log-file-max-mb",
    "-fmb",
    "log_file_max_mb",
    default=VARS_CLIENT.log_file_max_mb,
    help="Rollover -fn/--log-file-name at this many megabytes.",
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--log-file-max-files",
    "-fmf",
    "log_file_max_files",
    default=VARS_CLIENT.log_file_max_files,
    help="Keep this many rollover logs.",
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--proxy",
    "-p",
    "proxy",
    default=VARS_CLIENT.proxy,
    help="Proxy to use to connect to Axonius.",
    metavar="PROXY",
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--cert-client-both",
    "-ccb",
    "cert_client_both",
    help="Mutual TLS: file with both the certificate and unenencrypted private key of client cert.",
    metavar="PATH",
    show_envvar=True,
    show_default=False,
)
@click.option(
    "--cert-client-cert",
    "-ccc",
    "cert_client_cert",
    help=(
        "Mutual TLS: file with just the certificate of client cert "
        "(must also supply --cert-client-key)."
    ),
    metavar="PATH",
    show_envvar=True,
    show_default=False,
)
@click.option(
    "--cert-client-key",
    "-cck",
    "cert_client_key",
    help=(
        "Mutual TLS: file with just the unencrypted private key of client cert "
        "(must also supply --cert-client-cert)."
    ),
    metavar="PATH",
    show_envvar=True,
    show_default=False,
)
@click.option(
    "--certpath",
    "-cp",
    "certpath",
    help="File with SSL certificate for verifying the certificate offered by Axonius.",
    metavar="PATH",
    show_envvar=True,
    show_default=False,
)
@click.option(
    "--certverify/--no-certverify",
    "-cv/-ncv",
    "certverify",
    default=VARS_CLIENT.certverify,
    help="Perform SSL Certificate Verification.",
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--certwarn/--no-certwarn",
    "-cw/-ncw",
    "certwarn",
    default=VARS_CLIENT.certwarn,
    help="Disable warnings for self-signed SSL certificates.",
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--wraperror/--no-wraperror",
    "-we/-nw",
    "wraperror",
    default=VARS_CLIENT.wraperror,
    help="Show the full traceback of exceptions instead of a wrapped error.",
    is_flag=True,
    show_envvar=True,
)
@click.option(
    "--timeout-connect",
    "-tc",
    "timeout_connect",
    default=VARS_CLIENT.timeout_connect,
    help="Seconds to wait for connections to API",
    show_envvar=True,
    show_default=True,
)
@click.option(
    "--timeout-response",
    "-tr",
    "timeout_response",
    default=VARS_CLIENT.timeout_response,
    help="Seconds to wait for responses from API",
    show_default=True,
)
@click.version_option(version.__version__)
@context.pass_context
@click.pass_context
def cli(click_ctx, ctx, quiet, **kwargs):
    """Command line interface for the Axonius API Client."""
    try:
        cli_args = sys.argv
    except Exception:  # pragma: no cover
        cli_args = "No sys.argv!"

    PACKAGE_LOG.debug(f"sys.argv: {cli_args}")
    ctx._click_ctx = click_ctx
    ctx.QUIET = quiet
    ctx._connect_args.update(kwargs)


cli.add_command(grp_adapters.adapters)
cli.add_command(grp_assets.devices)
cli.add_command(grp_assets.users)
cli.add_command(grp_assets.vulnerabilities)
cli.add_command(grp_system.system)
cli.add_command(grp_tools.tools)
cli.add_command(grp_openapi.openapi)
cli.add_command(grp_certs.certs)
cli.add_command(grp_enforcements.enforcements)
