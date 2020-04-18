from tortoise import fields


class TimestampMixin:
    created_at = fields.DatetimeField(auto_now_add=True)
