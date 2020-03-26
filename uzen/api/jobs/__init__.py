from typing import List
from loguru import logger

from uzen.models.classifications import Classification
from uzen.models.dns_records import DnsRecord
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.services.classifications import ClassificationBuilder
from uzen.services.dns_records import DnsRecordBuilder
from uzen.services.scripts import ScriptBuilder


async def create_scripts(snapshot: Snapshot, insert_to_db=True) -> List[Script]:
    try:
        scripts = ScriptBuilder.build_from_snapshot(snapshot)
        if insert_to_db:
            await Script.bulk_create(scripts)
    except Exception as e:
        logger.error(
            f"Failed to process create_scrpts job. URL: {snapshot.url} / Error: {e}"
        )

    return scripts


async def create_dns_records(snapshot: Snapshot, insert_to_db=True) -> List[DnsRecord]:
    try:
        records = DnsRecordBuilder.build_from_snapshot(snapshot)
        if insert_to_db:
            await DnsRecord.bulk_create(records)
    except Exception as e:
        logger.error(
            f"Failed to process create_dns_records job. URL: {snapshot.url} / Error: {e}"
        )

    return records


async def create_classifications(
    snapshot: Snapshot, insert_to_db=True
) -> List[Classification]:
    try:
        classifications = ClassificationBuilder.build_from_snapshot(snapshot)
        if insert_to_db:
            await Classification.bulk_create(classifications)
    except Exception as e:
        logger.error(
            f"Failed to process create_classifications job. URL: {snapshot.url} / Error: {e}"
        )

    return classifications
