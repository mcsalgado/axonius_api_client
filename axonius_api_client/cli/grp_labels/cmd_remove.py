# -*- coding: utf-8 -*-
"""Command line interface for Axonius API Client."""
from ..context import CONTEXT_SETTINGS, click
from ..options import add_options
from .grp_common import handler
from .grp_options import LABELS_ACT as OPTIONS

METHOD = "remove"


@click.command(name=METHOD, context_settings=CONTEXT_SETTINGS)
@add_options(OPTIONS)
@click.pass_context
def cmd(ctx, url, key, secret, **kwargs):
    """Remove labels (tags) from assets."""
    handler(ctx=ctx, url=url, key=key, secret=secret, method=METHOD, **kwargs)
