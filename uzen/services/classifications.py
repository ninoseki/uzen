import json
from typing import List, Optional

from pysafebrowsing import SafeBrowsing
from pysafebrowsing.api import SafeBrowsingInvalidApiKey, SafeBrowsingWeirdError

from uzen.core import settings
from uzen.models.classifications import Classification
from uzen.models.snapshots import Snapshot


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
