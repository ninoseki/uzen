import asyncio
from typing import Optional

from async_lru import alru_cache
from asyncwhois.errors import QueryError, WhoIsError


async def aio_from_whois_cmd(hostname: str, timeout: int):
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

    return query_result


class Whois:
    @staticmethod
    @alru_cache()
    async def lookup(hostname: str) -> Optional[str]:
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
