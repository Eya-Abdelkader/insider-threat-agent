import logging
import socket
import threading
import time
from typing import Callable, Optional

log = logging.getLogger("dns_resolver")

CACHE_TTL = 300
LOOKUP_TIMEOUT= 1.5

class DNSResolver:
    def __init__(self):
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock =threading.Lock()

    def resolve_async (self, ip: str, callback:Callable[[str, str], None]) -> None:
        cached = self._get_cached(ip)
        if cached is not None:
            callback(ip, cached)
            return
        t= threading.Thread(
            target = self._lookup_and_call,
            args=(ip, callback),
            daemon=True,
            name=f"dns-{ip}",
        ) 
        t.start()

    def _lookup_and_call(self, ip: str, callback:Callable[[str, str],None]) -> None:
        hostname= self._lookup(ip)
        callback(ip, hostname)

    def _lookup(self, ip:str) -> str:
        result: list[str]=[]
        error: list[Exception]=[] 
        def _do_lookup() :
            try:
                name = socket.getnameinfo((ip,0),0)[0]
                result.append(name)
            except (socket.herror, socket.gaierror, OSError) as e:
                error.append(e)

        t = threading.Thread(target=_do_lookup, daemon=True)
        t.start()
        t.join(timeout=LOOKUP_TIMEOUT)
        if result:
            hostname= result[0]
            if hostname == ip :
                hostname= ip 
            else:
                log.info("DNS resolved: %s -> %s " , ip, hostname)
        else: 
            if error :
                log.debug("DNS lookup failed for %s : %s", ip, error[0])
            else:
                log.debug("DNS lookup timed out for %s", ip)
            hostname = ip
        with self._lock:
            self._cache[ip] = (hostname, time.time() + CACHE_TTL)
        return hostname


    def _get_cached(self, ip:str) -> Optional[str]:
        with self._lock:
            entry = self._cache.get(ip)
            if entry is None:
                return None
            hostname, expires_at = entry
            if time.time() < expires_at:
                return hostname
            del self._cache[ip]
            return None
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)                                                                       