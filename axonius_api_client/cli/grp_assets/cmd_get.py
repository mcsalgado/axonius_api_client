# -*- coding: utf-8 -*-
"""Command line interface for Axonius API Client."""
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import click

from .. import cli_constants, options
from . import grp_common


@click.command(name="get", context_settings=cli_constants.CONTEXT_SETTINGS)
@options.OPT_URL
@options.OPT_KEY
@options.OPT_SECRET
@options.OPT_EXPORT_FILE
@options.OPT_EXPORT_PATH
@options.OPT_EXPORT_FORMAT
@options.OPT_EXPORT_OVERWRITE
@options.OPT_EXPORT_DELIM
@options.OPT_EXPORT_TABLE_FORMAT
@options.OPT_QUERY
@options.OPT_QUERY_FILE
@options.OPT_FIELDS
@options.OPT_FIELDS_REGEX
@options.OPT_FIELDS_DEFAULT
@options.OPT_MAX_ROWS
@options.OPT_PAGE_START
@options.OPT_PAGE_SIZE
@click.pass_context
def cmd(
    ctx,
    url,
    key,
    secret,
    export_format,
    export_file,
    export_path,
    export_overwrite,
    export_delim,
    export_table_format,
    query,
    query_file,
    fields,
    fields_regex,
    fields_default,
    max_rows,
    page_size,
    page_start,
):
    """Get assets from a query."""
    if query_file:
        query = query_file.read()

    p_grp = ctx.parent.command.name

    client = ctx.obj.start_client(url=url, key=key, secret=secret)
    api = getattr(client, p_grp)

    with ctx.obj.exc_wrap(wraperror=ctx.obj.wraperror):
        raw_data = api.get(
            query=query,
            fields=fields,
            fields_regex=fields_regex,
            fields_default=fields_default,
            max_rows=max_rows,
            page_size=page_size,
            page_start=page_start,
        )

    grp_common.echo_response(ctx=ctx, raw_data=raw_data, api=api)

    formatters = grp_common.FORMATTERS

    ctx.obj.handle_export(
        raw_data=raw_data,
        formatters=formatters,
        export_format=export_format,
        export_file=export_file,
        export_path=export_path,
        export_overwrite=export_overwrite,
        table_format=export_table_format,
        joiner=export_delim,
    )
