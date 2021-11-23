from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from tortoise.exceptions import DoesNotExist, IntegrityError

from app import models, schemas, types
from app.api.dependencies.rule import SearchFilters
from app.api.dependencies.verification import verify_api_key
from app.services.searchers.rule import RuleSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=schemas.RulesSearchResults,
    summary="Search rules",
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
    summary="Get a rule",
)
async def get(rule_id: types.ULID) -> schemas.Rule:
    try:
        rule = await models.Rule.get_by_id(rule_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{rule_id} is not found")

    return rule.to_model()


@router.put(
    "/{rule_id}",
    response_model=schemas.Rule,
    summary="Update a rule",
)
async def put(
    rule_id: types.ULID,
    payload: schemas.UpdateRulePayload,
    _: Any = Depends(verify_api_key),
) -> schemas.Rule:
    try:
        rule = await models.Rule.get(id=rule_id)

        if payload.name is not None:
            rule.name = payload.name

        if payload.target is not None:
            rule.target = payload.target

        if payload.source is not None:
            rule.source = payload.source

        rule.allowed_network_addresses = payload.allowed_network_addresses
        rule.disallowed_network_addresses = payload.disallowed_network_addresses

        rule.allowed_resource_hashes = payload.allowed_resource_hashes
        rule.disallowed_resource_hashes = payload.disallowed_resource_hashes

        await rule.save()
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{rule_id} is not found")

    return rule.to_model()


@router.post(
    "/",
    response_model=schemas.Rule,
    summary="Create a rule",
    status_code=201,
)
async def create(
    payload: schemas.CreateRulePayload, _: Any = Depends(verify_api_key)
) -> schemas.Rule:
    rule = models.Rule(
        name=payload.name,
        target=payload.target,
        source=payload.source,
        allowed_network_addresses=payload.allowed_network_addresses,
        disallowed_network_addresses=payload.disallowed_network_addresses,
        allowed_resource_hashes=payload.allowed_resource_hashes,
        disallowed_resource_hashes=payload.disallowed_resource_hashes,
    )
    try:
        await rule.save()
        return rule.to_model()
    except IntegrityError:
        raise HTTPException(
            status_code=400,
            detail=f"{payload.name} is already registered as a rule's name",
        )


@router.delete(
    "/{rule_id}",
    summary="Delete a rule",
    status_code=204,
)
async def delete(
    rule_id: types.ULID, _: Any = Depends(verify_api_key)
) -> Dict[str, Any]:
    try:
        await models.Rule.delete_by_id(rule_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Rule:{rule_id} is not found")

    return {}
