import sys
import os
import logging
from datetime import datetime, timezone
from typing import Optional

_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)
import db
import net_monitor.config as config

import psutil

log = logging.getLogger("port_baseline")


class PortBaseline:


    def __init__(self):
        self._state: dict[tuple, dict] = {}

    def build(self):
      
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            log.warning("Cannot read connections — running without root. "
                        "Port baseline will be empty.")
            return

        for conn in conns:
            if conn.status != 'LISTEN' or not conn.laddr:
                continue
            if conn.laddr.port in config.IGNORED_LISTEN_PORTS:
                continue

            key = (conn.laddr.ip, conn.laddr.port)
            self._state[key] = {"pid": conn.pid}

            db.write_event("PORT_EVENT", {
            "event_type":   "baseline",
            "listening_on": conn.laddr.ip,
            "port":         conn.laddr.port,
            "pid":          conn.pid,
            "exe":          _resolve_exe(conn.pid),
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            })            

        log.info("Port baseline built: %d listening ports", len(self._state))

    def process_bind(self, event: dict) -> list:
        ip   = event.get("ip", "")
        port = event.get("port", 0)

        if not ip or not port:
            return []

        if port in config.IGNORED_LISTEN_PORTS:
            return []

        key    = (ip, port)
        events = []

        if key not in self._state:
            was_local  = ("127.0.0.1", port) in self._state
            event_type = "exposure_change" if (
                was_local and ip == "0.0.0.0"
            ) else "new"

            if event_type == "exposure_change":
                log.warning(
                    "Port exposure change: %d moved 127.0.0.1 → 0.0.0.0 "
                    "(exe=%s)", port, event.get("exe")
                )
            else:
                log.info("New port bound: %s:%d (exe=%s)",
                         ip, port, event.get("exe"))

            events.append({
                "event_type":   event_type,
                "listening_on": ip,
                "port":         port,
                "pid":          event.get("pid"),
                "exe":          event.get("exe"),
                "username":     event.get("username"),
                "timestamp":    datetime.now(timezone.utc).isoformat(),
            })

            self._state[key] = {
                "pid": event.get("pid"),
                "exe": event.get("exe"),
            }

        return events


def _resolve_exe(pid: Optional[int]) -> str:
    if not pid:
        return "unknown"
    try:
        return psutil.Process(pid).exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"        