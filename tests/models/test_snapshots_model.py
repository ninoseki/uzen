import json
import pytest

from uzen.models import Snapshot
from tests.utils import make_snapshot


def test_to_dict():
    snapshot = make_snapshot()
    d = snapshot.to_dict()
    assert isinstance(d, dict)
    assert d.get("url") == "http://example.com"
