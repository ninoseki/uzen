from typing import List

from fastapi import APIRouter, Depends

from uzen.api.dependencies.classifications import classification_filters
from uzen.models.schemas.classifications import Classification
from uzen.services.classification_searcher import ClassificationSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=List[Classification],
    response_description="Returns a list of matched classification",
    summary="Search classifications",
    description="Searcn classifications with filters",
)
async def search(
    filters: dict = Depends(classification_filters),
) -> List[Classification]:
    classifications = await ClassificationSearcher.search(filters)
    return [classification.to_model() for classification in classifications]
