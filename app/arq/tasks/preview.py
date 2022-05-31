from app import schemas
from app.services.browser import Browser


async def preview_task(ctx_: dict, hostname: str) -> schemas.JobResultWrapper:
    screenshot = await Browser.preview(hostname)
    return schemas.JobResultWrapper(result=screenshot, error=None)
