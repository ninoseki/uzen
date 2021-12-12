from typing import List, TypeVar

T = TypeVar("T")


def chunknize(list_: List[T], *, chunk_size: int = 100) -> List[List[T]]:
    return [list_[i : i + chunk_size] for i in range(0, len(list_), chunk_size)]
