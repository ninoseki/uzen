from datetime import date, datetime
from typing import Union, cast


def convert_to_datetime(d: Union[datetime, date]) -> datetime:
    if type(d) == datetime:
        return cast(datetime, d)

    return datetime.combine(cast(date, d), datetime.min.time())
