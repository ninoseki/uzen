from typing import List

from fastapi import APIRouter, Depends

from uzen.api.dependencies.scripts import script_filters
from uzen.models.scripts import ScriptModel
from uzen.services.script_searcher import ScriptSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=List[ScriptModel],
    response_description="Returns a list of matched scripts",
    summary="Search scripts",
    description="Searcn scripts with filters",
)
async def search(filters: dict = Depends(script_filters),) -> List[ScriptModel]:
    scripts = await ScriptSearcher.search(filters)
    return [script.to_full_model() for script in scripts]
