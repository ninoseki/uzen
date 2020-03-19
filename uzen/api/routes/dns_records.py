from typing import List

from fastapi import APIRouter, Depends

from uzen.api.dependencies.scripts import script_filters
from uzen.models.dns_records import DnsRecordModel
from uzen.services.dns_record_searcher import DnsRecordSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=List[DnsRecordModel],
    response_description="Returns a list of matched DNS records",
    summary="Search DNS records",
    description="Searcn DNS records with filters",
)
async def search(filters: dict = Depends(script_filters)) -> List[DnsRecordModel]:
    records = await DnsRecordSearcher.search(filters)
    return [record.to_full_model() for record in records]
