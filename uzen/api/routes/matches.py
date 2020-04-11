from typing import List, Optional, cast

from fastapi import APIRouter

from uzen.models.matches import Match
from uzen.schemas.common import CountResponse
from uzen.schemas.matches import Match as MatchModel
from uzen.services.searchers.matches import MatchSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=List[MatchModel],
    response_description="Returns a list of matches",
    summary="Search matches",
    description="Searcn matches with filters",
)
async def search(
    size: Optional[int] = None, offset: Optional[int] = None, filters: dict = {}
) -> List[MatchModel]:
    matches = await MatchSearcher.search(filters, size=size, offset=offset)
    matches = cast(List[Match], matches)

    return [match.to_model() for match in matches]


@router.get(
    "/count",
    response_model=CountResponse,
    response_description="Returns a count matched matches",
    summary="Count rules",
    description="Count a number of matches matched with filters",
)
async def count(filters: dict = {}) -> CountResponse:
    count = await MatchSearcher.search(filters, count_only=True)
    return CountResponse(count=count)
