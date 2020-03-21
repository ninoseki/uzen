from typing import List

from fastapi import APIRouter, Depends

from uzen.api.dependencies.scripts import script_filters
from uzen.models.schemas.scripts import Script
from uzen.services.script_searcher import ScriptSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=List[Script],
    response_description="Returns a list of matched scripts",
    summary="Search scripts",
    description="Searcn scripts with filters",
)
async def search(filters: dict = Depends(script_filters),) -> List[Script]:
    scripts = await ScriptSearcher.search(filters)
    return [script.to_model() for script in scripts]
