import sentry_sdk

from app.core import settings


def init_sentry() -> None:
    if settings.SENTRY_DNS is None:
        return

    sentry_sdk.init(
        str(settings.SENTRY_DNS),
        traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
    )
