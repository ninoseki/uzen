from tortoise.fields.data import JSONField


class CustomJSONField(JSONField):
    class _db_mysql:
        SQL_TYPE = "MEDIUMTEXT"
