from typing import List, Optional, cast

from fastapi import APIRouter, Depends, HTTPException
from tortoise.exceptions import DoesNotExist

from uzen.api.dependencies.rules import search_filters
from uzen.models.rules import Rule
from uzen.models.schemas.common import CountResponse
from uzen.models.schemas.rules import CreateRulePayload
from uzen.models.schemas.rules import Rule as RuleModel
from uzen.services.searchers.rules import RuleSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=List[RuleModel],
    response_description="Returns a list of matched rules",
    summary="Search rules",
    description="Searcn rules with filters",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: dict = Depends(search_filters),
) -> List[RuleModel]:
    rules = await RuleSearcher.search(filters, size=size, offset=offset)
    rules = cast(List[Rule], rules)

    return [rule.to_model() for rule in rules]


@router.get(
    "/count",
    response_model=CountResponse,
    response_description="Returns a count matched rules",
    summary="Count rules",
    description="Count a number of rules matched with filters",
)
async def count(filters: dict = Depends(search_filters)) -> CountResponse:
    count = await RuleSearcher.search(filters, count_only=True)
    return CountResponse(count=count)


@router.get(
    "/{rule_id}",
    response_model=RuleModel,
    response_description="Returns a rule",
    summary="Get a rule",
    description="Get a rule which has a given id",
)
async def get(rule_id: int) -> RuleModel:
    try:
        rule = await Rule.get(id=rule_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{id} is not found")

    return rule.to_model()


@router.post(
    "/",
    response_model=RuleModel,
    response_description="Returns a created rule",
    summary="Create a rule",
    description="Create a rule",
    status_code=201,
)
async def create(payload: CreateRulePayload) -> RuleModel:
    rule = Rule(name=payload.name, target=payload.target, source=payload.source)
    await rule.save()
    return rule.to_model()


@router.delete(
    "/{rule_id}",
    response_description="Returns an empty JSON",
    summary="Delete a rule",
    description="Delete a rule which has a given ID",
    status_code=204,
)
async def delete(rule_id: int) -> dict:
    try:
        rule = await Rule.get(id=rule_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{id} is not found")

    await rule.delete()
    return {}
