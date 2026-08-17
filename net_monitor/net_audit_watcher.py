
import os
import time
import logging
import threading
from typing import Callable, Optional

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)


import net_monitor.config as config
from net_monitor.net_parser import parse_syscall_line, parse_sockaddr_line, correlate    
from audit_router import AuditRouter

log = logging.getLogger("net_audit_watcher")


class NetAuditWatcher:
    

    def __init__(self, on_event: Callable[[dict], None], router:AuditRouter):
        
        self._on_event   = on_event
        self._router= router
        self._pending: dict[str, dict] = {}

    def start(self):

        self._router.register(config.AUDIT_KEY, self._process_line)
        log.info("NetAuditWatcher started on %s", config.AUDIT_LOG_PATH)

    def stop(self):
       
        log.info("NetAuditWatcher stopped")

    def _process_line(self, line: str):
        
        if not line:
            return

        is_syscall  = "type=SYSCALL"  in line
        is_sockaddr = "type=SOCKADDR" in line

        if not is_syscall and not is_sockaddr:
            return

        if is_syscall and f'key="{config.AUDIT_KEY}"' not in line:
            return

        if is_syscall:
            syscall_data = parse_syscall_line(line)
            if syscall_data:
                self._pending[syscall_data["msg_id"]] = syscall_data
            return

        if is_sockaddr:
            sockaddr_data = parse_sockaddr_line(line)
            if not sockaddr_data:
                return

            msg_id       = sockaddr_data["msg_id"]
            syscall_data = self._pending.pop(msg_id, None)

            if syscall_data:
                event = correlate(syscall_data, sockaddr_data)
                if event:
                    self._on_event(event)
                self._router.release_msg_id(msg_id, config.AUDIT_KEY)    

        if len(self._pending) > 1000:
            self._pending.clear()
            log.debug("Pending buffer cleared (>1000 unmatched SYSCALLs)")


   