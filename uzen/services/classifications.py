from pysafebrowsing import SafeBrowsing
from pysafebrowsing.api import SafeBrowsingInvalidApiKey, SafeBrowsingWeirdError

from typing import Optional, List
import json

from uzen.models.classifications import Classification
from uzen.models.snapshots import Snapshot
from uzen.core import settings


def google_safe_brwosing_lookup(url: str) -> Optional[dict]:
    key = str(settings.GOOGLE_SAFE_BROWSING_API_KEY)
    if key == "":
        return None

    try:
        s = SafeBrowsing(key)
        return s.lookup_url(url)
    except (SafeBrowsingInvalidApiKey, SafeBrowsingWeirdError):
        pass

    return None


class ClassificationBuilder:
    @staticmethod
    def build_from_snapshot(snapshot: Snapshot) -> List[Classification]:
        classifications = []

        res = google_safe_brwosing_lookup(snapshot.url)
        if res is not None:
            malicious = bool(res.get("malicious"))
            classifications.append(
                Classification(
                    name="Google Safe Browsing",
                    malicious=malicious,
                    snapshot_id=snapshot.id or -1,
                )
            )

        return classifications
