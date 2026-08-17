import logging
import os 
import threading
import time 
from dataclasses import dataclass , field
from typing import Optional

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import db 
from net_monitor.dns_resolver import DNSResolver 

log = logging.getLogger("connection_aggregator")
FLUSH_INTERVAL = 30.0
MAX_BUCKET_SIZE= 1000

BROWSER_PORTS = {80, 443, 8080, 8443}
BROWSER_NAMES = {"firefox", "chrome", "chromium", "brave-browser", "brave", "opera", "vivaldi",  "epiphany"}

def _is_browser (exe: Optional[str]) -> bool :
    if not exe :
        return False
    name = os.path.basename(exe).lower()
    return any(b in name for b in BROWSER_NAMES)

@dataclass
class _Bucket:
    exe : str
    ip : str
    port : str
    first_seen : float   
    last_seen : float
    count : int =1
    sample : dict=field(default_factory=dict)

class ConnectionAggregator:

    def __init__ (self):
        self._buckets : dict[tuple, _Bucket] = {}
        self._lock = threading.Lock()
        self._dns = DNSResolver()
        self._stop_event = threading.Event()
        self._flush_thread= threading.Thread(
            target = self._flush_loop,
            daemon = True,
            name = "conn-aggregation-flush",
        )   
    def start(self) -> None:
        self._flush_thread.start()
        log.info("ConnectionAggregator started ""(flush_interval=%.0fs, max_bucket=%d)",FLUSH_INTERVAL, MAX_BUCKET_SIZE)

    def stop (self) -> None:
        self._stop_event.set()
        self._flush_thread.join(timeout=5)
        self._flush_all (reason = "shutdown")
        log.info("ConnectionAggregator stopped ""(dns_cache_size=%d)", self._dns.cache_size())

    def process(self, event: dict) -> None:
        exe = event.get("exe") or ""
        ip = event.get("ip") or ""
        port = event.get("port") or 0

        if _is_browser(exe):
            self._aggregate(exe, ip, port, event)
        else :
            event_type = event.get("event" , "CONNECTION_ATTEMPT")
            def on_resolved(resolver_ip:str, hostname: str) -> None:
                event["hostname"] = hostname
                db.write_event(event_type, event)
            self._dns.resolve_async(ip , on_resolved)   

    def _aggregate(self, exe: str , ip: str , port: int, event: dict) -> None:
        key = (exe, port)
        now = time.time()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                self._buckets[key] = _Bucket(
                    exe=exe, ip=ip,port=port,
                    first_seen=now, last_seen=now, count=1,sample=event,
                )         
                return 
            bucket.count +=1
            bucket.last_seen=now
            if bucket.port == 0 and port != 0:
                bucket.port = port

            if bucket.count >= MAX_BUCKET_SIZE:
                del self._buckets[key]
                self._emit(bucket, reason = "max_size") 

    def _flush_loop (self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout= FLUSH_INTERVAL)
            self._flush_stale()

    def _flush_stale(self) -> None:
        now = time.time()
        to_emit: list[_Bucket] = []
        with self._lock:
            stale=[
                k for k, b in self._buckets.items()
                if now - b.last_seen >= FLUSH_INTERVAL

            ]   
            for k in stale :
                to_emit.append(self._buckets.pop(k)) 

        for bucket in to_emit:
            self._emit(bucket, reason="timeout")  

    def _flush_all(self, reason:str = "shutdown") -> None:
        with self._lock:
            buckets = list(self._buckets.values()) 
            self._buckets.clear()
        for bucket in buckets:
            self._emit(bucket, reason=reason)      


    def _emit (self, bucket:_Bucket, reason: str) -> None:

        sample = bucket.sample
        duration = bucket.last_seen - bucket.first_seen
        payload={
            "event":        "NET_CONNECTION_AGGREGATED",
            "exe":          bucket.exe,
            "ip":           bucket.ip,
            "port":         bucket.port,
            "family":       sample.get("family"),
            "pid":          sample.get("pid"),
            "ppid":         sample.get("ppid"),
            "uid":          sample.get("uid"),
            "auid":         sample.get("auid"),
            "username":     sample.get("username"),
            "comm":         sample.get("comm"),
            "direction":    sample.get("direction"),
            "local_ip":     sample.get("local_ip"),
            "local_port":   sample.get("local_port"),
            "interface":    sample.get("interface"),
            "count":        bucket.count,
            "first_seen":   bucket.first_seen,
            "last_seen":    bucket.last_seen,
            "duration_s":   round(duration, 2),
            "flush_reason": reason,
        }
        def on_resolved(ip: str , hostname: str) -> None:
            payload["hostname"] = hostname
            db.write_event("NET_CONNECTION_AGGREGATED", payload)
            log.info("AGGREGATED %s -> %s (%s):%d  count=%d  ""duration=%.1fs  reason=%s",os.path.basename(bucket.exe),hostname, ip, bucket.port,bucket.count, duration, reason,)
        self._dns.resolve_async(bucket.ip, on_resolved)    

                              



