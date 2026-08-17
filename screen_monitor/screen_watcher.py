import os
import time
import logging
import threading
from typing import Callable, Optional

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import screen_monitor.config as config
from screen_monitor.screen_parser import (parse_syscall_line, parse_execve_line,
                                           parse_path_line, correlate, _extract_msg_id)
 
from audit_router import AuditRouter
 
log = logging.getLogger("screen_watcher")
 
 
class Screen_Watcher:
 
    def __init__(self,
                 on_event: Callable[[dict], None],
                 inode_map: dict[int, str],
                 tool_paths: dict[str, str], router:AuditRouter):
       
        self._on_event   = on_event
        self._inode_map  = inode_map
        self._tool_paths = tool_paths
        self._router = router
        self._pending: dict[str, dict] = {}
 
    def start(self):
        self._router.register(config.AUDIT_KEY, self._process_line)
        log.info("ScreenWatcher started on %s", config.AUDIT_LOG_PATH)
 
    def stop(self):
        log.info("ScreenWatcher stopped")
 
    def _process_line(self, line: str):

        if not line:
            return
 
        is_syscall = "type=SYSCALL" in line
        is_execve  = "type=EXECVE"  in line
        is_path    = "type=PATH"    in line
 
        if not any([is_syscall, is_execve, is_path]):
            return
 
        if is_syscall and f'key="{config.AUDIT_KEY}"' not in line:
            return
 
        if is_syscall:
            data = parse_syscall_line(line)
            if data:
                msg_id = data["msg_id"]
                self._pending[msg_id] = {
                    "syscall": data,
                    "execve":  None,
                    "path":    None,
                }
            return
 
        if is_execve:
            data = parse_execve_line(line)
            if data:
                msg_id = data["msg_id"]
                if msg_id in self._pending:
                    self._pending[msg_id]["execve"] = data
                    self._attempt_correlation(msg_id)
            return
 
        if is_path:
            data = parse_path_line(line)
            if data:
                msg_id = data["msg_id"]
                if msg_id in self._pending:
                    self._pending[msg_id]["path"] = data
                    if self._pending[msg_id].get("execve"):
                        self._attempt_correlation(msg_id)
                    
            return
 
        if len(self._pending) > 500:
            self._pending.clear()
            log.debug("Pending buffer cleared")
 
    def _attempt_correlation(self, msg_id: str):

        entry = self._pending.pop(msg_id, None)
        if not entry:
            return
 
        syscall_data = entry.get("syscall")
        if not syscall_data:
            return   

 
        event = correlate(syscall_data, entry.get("execve"), entry.get("path"),
                          self._inode_map, self._tool_paths)
        if event:
            self._on_event(event)
        self._router.release_msg_id(msg_id, config.AUDIT_KEY)
 
