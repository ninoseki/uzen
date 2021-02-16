import socket
from typing import Optional

import asyncwhois
from async_lru import alru_cache
from asyncwhois.errors import WhoIsError


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
            result = await asyncwhois.aio_lookup(hostname)
        except (
            WhoIsError,
            socket.timeout,
            ConnectionError,
            TimeoutError,
        ):
            return None

        return result.query_output
