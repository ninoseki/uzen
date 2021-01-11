from typing import List
from uuid import UUID

from tortoise.exceptions import IntegrityError

from app import dataclasses, models


async def save_script_files(
    script_files: List[dataclasses.ScriptFile], snapshot_id: UUID
):
    files = [script_file.file for script_file in script_files]
    for file in files:
        try:
            await file.save()
        except IntegrityError:
            # ignore the intergrity error
            # e.g. tortoise.exceptions.IntegrityError: UNIQUE constraint failed: files.id
            pass

    scripts = [script_file.script for script_file in script_files]
    for script in scripts:
        script.snapshot_id = snapshot_id
    await models.Script.bulk_create(scripts)
