from typing import Optional

from fastapi import APIRouter, Depends

from app.api.dependencies.matches import SearchFilters
from app.schemas.matches import SearchResults
from app.services.searchers.matches import MatchSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=SearchResults,
    response_description="Returns a list of matches",
    summary="Search matches",
    description="Searcn matches with filters",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> SearchResults:
    return await MatchSearcher.search(vars(filters), size=size, offset=offset)
