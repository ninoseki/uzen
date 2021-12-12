import pytest

from app.utils.chunk import chunknize


@pytest.mark.parametrize(
    "length,chunk_size,expected",
    [
        (100, 10, 10),
        (100, 100, 1),
        (100, 50, 2),
        (101, 50, 3),
        (0, 50, 0),
    ],
)
def test_chunknize(length: int, chunk_size: int, expected: int):
    list_ = list(range(length))
    assert len(chunknize(list_, chunk_size=chunk_size)) == expected
