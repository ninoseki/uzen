from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.api.dependencies.rule import SearchFilters
from app.services.searchers.rule import RuleSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=schemas.RulesSearchResults,
    response_description="Returns a list of matched rules",
    summary="Search rules",
    description="Searcn rules with filters",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> schemas.RulesSearchResults:
    return await RuleSearcher.search(vars(filters), size=size, offset=offset)


@router.get(
    "/{rule_id}",
    response_model=schemas.Rule,
    response_description="Returns a rule",
    summary="Get a rule",
    description="Get a rule which has a given id",
)
async def get(rule_id: UUID) -> schemas.Rule:
    try:
        rule = await models.Rule.get_by_id(rule_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{rule_id} is not found")

    return rule.to_model()


@router.put(
    "/{rule_id}",
    response_model=schemas.Rule,
    response_description="Returns a rule",
    summary="Update a rule",
    description="Update a rule which has a given id",
)
async def put(rule_id: UUID, payload: schemas.UpdateRulePayload) -> schemas.Rule:
    try:
        rule = await models.Rule.get(id=rule_id)
        if payload.name is not None:
            rule.name = payload.name
        if payload.target is not None:
            rule.target = payload.target
        if payload.source is not None:
            rule.source = payload.source
        await rule.save()
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{rule_id} is not found")

    return rule.to_model()


@router.post(
    "/",
    response_model=schemas.Rule,
    response_description="Returns a created rule",
    summary="Create a rule",
    description="Create a rule",
    status_code=201,
)
async def create(payload: schemas.CreateRulePayload) -> schemas.Rule:
    rule = models.Rule(name=payload.name, target=payload.target, source=payload.source)
    await rule.save()
    return rule.to_model()


@router.delete(
    "/{rule_id}",
    response_description="Returns an empty JSON",
    summary="Delete a rule",
    description="Delete a rule which has a given ID",
    status_code=204,
)
async def delete(rule_id: UUID) -> dict:
    try:
        await models.Rule.delete_by_id(rule_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{rule_id} is not found")

    return {}
