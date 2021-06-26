from datetime import datetime, timedelta
from typing import Any, List, Optional, Union

from arq.constants import default_queue_name
from arq.jobs import Job, JobDef


class FakeArqRedis:
    async def enqueue_job(
        self,
        function: str,
        *args: Any,
        _job_id: Optional[str] = None,
        _queue_name: Optional[str] = None,
        _defer_until: Optional[datetime] = None,
        _defer_by: Union[None, int, float, timedelta] = None,
        _expires: Union[None, int, float, timedelta] = None,
        _job_try: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[Job]:
        return Job("dummy", redis=self, _queue_name=_queue_name, _deserializer=None)

    async def queued_jobs(
        self, *, queue_name: str = default_queue_name
    ) -> List[JobDef]:
        return []
