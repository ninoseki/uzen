import asyncio
import datetime
from typing import Dict, Optional, Union

import dateparser
from async_lru import alru_cache
from asyncwhois.errors import NotFoundError, QueryError, WhoIsError
from asyncwhois.parser import WhoIsParser

from app import dataclasses


def build_parser(hostname: str) -> WhoIsParser:
    tld = hostname.split(".")[-1]
    return WhoIsParser(tld)


def normalize_datetime(
    input: Optional[Union[datetime.datetime, str]]
) -> Optional[datetime.datetime]:
    if input is None:
        return input

    if isinstance(input, datetime.datetime):
        return input

    return dateparser.parse(input)


def parse(raw: str, hostname: str) -> dataclasses.Whois:
    output: Dict[str, Optional[Union[str, datetime.datetime]]] = {}
    try:
        parser = build_parser(hostname)
        parser.parse(raw)
        output = parser.parser_output
    except NotFoundError:
        pass

    created = normalize_datetime(output.get("created"))
    updated = normalize_datetime(output.get("updated"))
    expires = normalize_datetime(output.get("expires"))

    return dataclasses.Whois(
        content=raw,
        created=created,
        updated=updated,
        expires=expires,
        registrar=output.get("registrar"),
        registrant_name=output.get("registrant_name"),
        registrant_organization=output.get("registrant_organization"),
    )


async def aio_from_whois_cmd(hostname: str, timeout: int) -> dataclasses.Whois:
    # open a new process for "whois" command
    proc = await asyncio.create_subprocess_shell(
        f"whois {hostname}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        # block for query_result
        query_result, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        query_result = query_result.decode(errors="ignore")
    except asyncio.TimeoutError:
        raise QueryError(
            f'The shell command "whois {hostname}" exceeded timeout of {timeout} seconds'
        )

    return parse(query_result, hostname)


class Whois:
    @staticmethod
    @alru_cache()
    async def lookup(hostname: str) -> Optional[dataclasses.Whois]:
        """Perform Whois lookup

        Arguments:
            hostname {str} -- Hostname

        Returns:
            Optional[str] -- Whois response as a string, returns None if an error occurs
        """
        try:
            result = await aio_from_whois_cmd(hostname, timeout=5)
        except WhoIsError:
            return None

        return result
