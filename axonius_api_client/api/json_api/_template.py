# -*- coding: utf-8 -*-
"""Models for API requests & responses."""
import dataclasses
from typing import List, Optional

import marshmallow_jsonapi

from .base import BaseModel, BaseSchemaJson
from .custom_fields import get_schema_dc


class ExampleSchema(BaseSchemaJson):
    """Pass."""

    example_opt_str = marshmallow_jsonapi.fields.Str(
        allow_none=True,
        load_default=None,
        dump_default=None,
    )

    class Meta:
        """Pass."""

        type_ = "example_schema"

    @staticmethod
    def get_model_cls():
        """Pass."""
        return Example

    @classmethod
    def validate_attr_excludes(cls) -> List[str]:
        """Pass."""
        return ["document_meta", "id"]


@dataclasses.dataclass
class Example(BaseModel):
    """Pass."""

    example_opt_str: Optional[str] = get_schema_dc(
        schema=ExampleSchema,
        key="example_opt_str",
        default=None,
    )

    document_meta: Optional[dict] = dataclasses.field(default_factory=dict)

    @staticmethod
    def get_schema_cls():
        """Pass."""
        return ExampleSchema
