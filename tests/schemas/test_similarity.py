from typing import Optional

import pytest
from pydantic import ValidationError

from app.schemas.similarity import SimilarityScan

html = "<p>foo</p>"


@pytest.mark.parametrize(
    "threshold,error",
    [
        (-0.1, ValidationError),
        (1.1, ValidationError),
        (0.0, None),
        (0.5, None),
        (1.0, None),
    ],
)
def test_validation(threshold: Optional[float], error):
    if error is not None:
        with pytest.raises(error):
            SimilarityScan(html=html, threshold=threshold)
    else:
        payload = SimilarityScan(html=html, threshold=threshold)
        assert payload.threshold == threshold
