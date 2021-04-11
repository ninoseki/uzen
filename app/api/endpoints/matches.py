from typing import Optional

from fastapi import APIRouter, Depends

from app import schemas
from app.api.dependencies.match import SearchFilters
from app.services.searchers.match import MatchSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=schemas.MatchesSearchResults,
    response_description="Returns a list of matches",
    summary="Search matches",
    description="Search matches with filters",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> schemas.MatchesSearchResults:
    return await MatchSearcher.search(vars(filters), size=size, offset=offset)
