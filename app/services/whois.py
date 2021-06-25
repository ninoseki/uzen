import asyncio
from typing import Optional

import tldextract
from aiocache import Cache, cached
from aiocache.serializers import PickleSerializer
from whois_parser import WhoisParser

from app import dataclasses


def convert_hostname(hostname: str) -> str:
    extract_result = tldextract.extract(hostname)

    # for IP address
    if extract_result.suffix == "":
        return hostname

    tld = extract_result.suffix
    if len(tld.split(".")) > 1:
        tld = tld.split(".")[-1]

    return extract_result.domain + "." + tld


async def aio_from_whois_cmd(hostname: str, timeout: int) -> dataclasses.Whois:
    domain_and_tld = convert_hostname(hostname)

    # open a new process for "whois" command
    proc = await asyncio.create_subprocess_shell(
        f"whois {domain_and_tld}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # block for query_result
    query_result_, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    raw_text = query_result_.decode(errors="ignore")

    parser = WhoisParser()
    record = parser.parse(raw_text, hostname=hostname)

    return dataclasses.Whois(
        content=raw_text,
        created=record.registered_at,
        updated=record.updated_at,
        expires=record.expires_at,
        registrar=record.registrar,
        registrant_name=record.registrant.name,
        registrant_organization=record.registrant.organization,
    )


class Whois:
    @staticmethod
    @cached(ttl=60 * 10, cache=Cache.MEMORY, serializer=PickleSerializer())
    async def lookup(hostname: str) -> Optional[dataclasses.Whois]:
        """Perform Whois lookup

        Arguments:
            hostname {str} -- Hostname

        Returns:
            Optional[dataclass.Whois] -- Whois record, returns None if an error occurs
        """
        try:
            result = await aio_from_whois_cmd(hostname, timeout=5)
        except Exception:
            return None

        return result
