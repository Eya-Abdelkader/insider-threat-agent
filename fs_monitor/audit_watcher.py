import os
import time
import logging
import threading
from typing import Callable, Optional

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import fs_monitor.config as config
from fs_monitor.audit_parser import (parse_syscall_line, parse_path_line,
                                      parse_cwd_line, parse_proctitle_line,
                                      correlate)


from audit_router import AuditRouter                                      

log = logging.getLogger("audit_watcher")


class AuditWatcher:
  
    def __init__(self, on_event: Callable[[dict], None], router: AuditRouter):
        
        self._on_event    = on_event
        self._router = router
        self._pending: dict[str, dict] = {}

    def start(self):
        self._router.register(config.AUDIT_KEY, self._process_line)
        log.info("AuditWatcher démarré sur %s", config.AUDIT_LOG_PATH)

    def stop(self):
        log.info("AuditWatcher arrêté")


    def _process_line(self, line: str):
       
        if not line:
            return

        is_syscall = "type=SYSCALL" in line
        is_path    = "type=PATH"    in line

        is_cwd       = "type=CWD"       in line
        is_proctitle = "type=PROCTITLE" in line

        if not is_syscall and not is_path and not is_cwd and not is_proctitle:
            return   
        if is_syscall and f'key="{config.AUDIT_KEY}"' not in line:
            return   
        
        if is_cwd:
            cwd_data = parse_cwd_line(line)
            if cwd_data:
                self._pending[f"{cwd_data['msg_id']}_cwd"] = cwd_data["cwd"]
            return

        
        if is_proctitle:
            pt_data = parse_proctitle_line(line)
            if pt_data:
                self._pending[f"{pt_data['msg_id']}_proctitle"] = pt_data
            return

        
        syscall_data = parse_syscall_line(line)
        if syscall_data:
            self._pending[syscall_data["msg_id"]] = syscall_data
            return

        
        path_data = parse_path_line(line)
        if path_data:
            msg_id = path_data["msg_id"]
            item   = path_data.get("item", 0)

            
            existing = self._pending.get(f"{msg_id}_path")
            if existing is None or item > existing.get("item", -1):
                self._pending[f"{msg_id}_path"] = path_data

            syscall_data = self._pending.get(msg_id)
            if not (syscall_data and isinstance(syscall_data, dict)
                    and "action" in syscall_data):
                return

            action = syscall_data.get("action", "")

           
            if action in {"deleted", "moved"}:
                if item < 1:
                    
                    return

            best_path = self._pending.pop(f"{msg_id}_path", path_data)

            
            if (best_path.get("item", 0) == 0
                    and action in {"deleted", "moved"}):
                cwd       = self._pending.pop(f"{msg_id}_cwd", None)
                pt_data   = self._pending.pop(f"{msg_id}_proctitle", None)
                if cwd and pt_data and pt_data.get("arg"):
                    
                    arg      = pt_data["arg"]
                    fullpath = arg if arg.startswith("/") else os.path.join(cwd, arg)
                    best_path = {"msg_id": msg_id, "path": fullpath, "item": 1}
                    log.debug("Path reconstructed from CWD+PROCTITLE : %s", fullpath)

            syscall_data = self._pending.pop(msg_id, None)
            self._pending.pop(f"{msg_id}_cwd", None)
            self._pending.pop(f"{msg_id}_proctitle", None)

            if syscall_data:
                event = correlate(syscall_data, best_path)
                if event:
                    self._on_event(event)

                self._router.release_msg_id(msg_id, config.AUDIT_KEY)    
        if len(self._pending) > 1000:
            self._pending.clear()
            log.debug("Pending buffer cleared")    

       
