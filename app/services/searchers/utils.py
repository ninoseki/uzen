from datetime import date, datetime
from typing import Union


def convert_to_datetime(d: Union[datetime, date]) -> datetime:
    if isinstance(d, datetime):
        return d

    return datetime.combine(d, datetime.min.time())
