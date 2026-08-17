import os
import time 
import logging
import threading
from typing import Callable, Optional
import re

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import precursor_detector.config as config
from precursor_detector.precursor_parser import (parse_syscall_line, parse_execve_line, parse_path_line,  correlate)
from audit_router import AuditRouter


log= logging.getLogger("precursor_watcher")
RE_MSG_ID = re.compile(r'audit\((\d+\.\d+):(\d+)\)')

class PrecursorWatcher:

    def __init__(self, on_event:Callable[[dict], None], router: AuditRouter):
        self._on_event = on_event
        self._router = router
        self._sudo_commands: dict[str, str] = {}
        self._proctitles: dict[str, str] = {}
        self._seen_priv_pids: dict[str, float] = {}
        self._pending: dict[str, dict] = {}

    def start (self):
        for key in config.AUDIT_KEYS:
            self._router.register(key, self._process_line)
        log.info("PrecursorWatcher registered for keys=%s",list(config.AUDIT_KEYS))



    def stop(self):
  
        log.info("PrecursorWatcher stopped")

    def _process_line(self, line: str):
        if not line:
            
            return

        is_syscall= "type=SYSCALL"   in line
        is_execve = "type=EXECVE"    in line
        is_path    = "type=PATH"     in line
        is_proctitle = "type=PROCTITLE" in line 



        if not any([is_syscall, is_execve, is_path, is_proctitle]):
            return

        if is_proctitle:
            self._handle_proctitle(line)
            return   

        if is_syscall:
            has_key= any(f'key="{k}"' in line for k in config.AUDIT_KEYS)
            if not has_key:
                return
            data = parse_syscall_line(line)
            if not data :
                return

            msg_id = data["msg_id"]
            syscall = data.get("syscall","")

            if msg_id in self._pending:
                return            
            self._pending[msg_id] = {
                "syscall": data,
                "execve" : None,
                "path"   : None,
            }  

            if syscall in ("capset", "setuid", "setgid","setreuid", "setregid", "setresuid", "setresgid"):
                self._pending[msg_id]["ready"] = True      
            return   

        if is_execve:
            data = parse_execve_line(line)
            
            if data:
                msg_id = data["msg_id"]
                if msg_id in self._pending:
                    self._pending[msg_id]["execve"]= data 
                         
            return

        if is_path:
            data = parse_path_line(line)
            if data: 
                msg_id = data["msg_id"]
                if msg_id in self._pending:
                    self._pending[msg_id]["path"] = data

                    entry = self._pending.get(msg_id,{})
                    syscall = entry.get("syscall", {}).get("syscall", "")
                    if syscall in ("chmod", "fchmod","fchmodat"):
                        self._attempt_correlation(msg_id)

            return 

        if len(self._pending) > 1000:
            ready = [mid for mid, e in self._pending.items() if e.get("ready")]
            for mid in ready:
                self._attempt_correlation(mid)
            self._pending.clear()
            log.debug("Pending buffer cleared")

    def _attempt_correlation(self, msg_id: str):
        entry = self._pending.pop(msg_id, None)
        if not entry:
            return

        syscall_data = entry.get("syscall")
        if not syscall_data:
            return
 

        pid  = syscall_data.get("pid", "")
        ppid = syscall_data.get("ppid", "")

        proctitle = (
            entry.get("proctitle") or
            self._proctitles.pop(msg_id, None) or   
            ""
        )

        if proctitle and "sudo" in proctitle:
            self._sudo_commands[pid] = proctitle

        sudo_command = (
            self._sudo_commands.get(pid) or
            self._sudo_commands.get(ppid) or
            "unknown"
        )
        syscall_data["_sudo_command"] = sudo_command

        event = correlate(
            syscall_data,
            entry.get("execve"),
            entry.get("path"),
        )
        if not event:
            self._router.release_msg_id(msg_id, entry.get("key", ""))
            return

        category = event.get("category")

        if category in ("privilege_escalation", "capability_change"):
            pid = event.get("pid", "")
            now = time.time()
            self._seen_priv_pids = {
                p: t for p, t in self._seen_priv_pids.items()
                if now - t < 0.3
            }
            if pid in self._seen_priv_pids:
                self._router.release_msg_id(msg_id, entry.get("key", ""))
                return
            self._seen_priv_pids[pid] = now

        if category == "sudo_execution":
            pid      = event.get("pid", "")
            full_cmd = event.get("details", {}).get("full_command", "")
            if pid and full_cmd:
                self._sudo_commands[pid] = full_cmd

        if len(self._sudo_commands) > 50:
            oldest_keys = list(self._sudo_commands.keys())[:25]
            for k in oldest_keys:
                del self._sudo_commands[k]
        if len(self._proctitles) > 500:
            self._proctitles.clear()        

        self._on_event(event)
        self._router.release_msg_id(msg_id, entry.get("key", ""))


    def _handle_proctitle(self, line: str) -> None:
        
        msg_id_match = re.search(r'audit\((\d+\.\d+):(\d+)\)', line)
        if not msg_id_match:
            return
        msg_id = f"{msg_id_match.group(1)}:{msg_id_match.group(2)}"

        pt_match = re.search(r'proctitle=([0-9A-Fa-f]+)', line)
        if pt_match:
            hex_str = pt_match.group(1)
            try:
                raw   = bytes.fromhex(hex_str)
                parts = raw.split(b'\x00')
                parts = [p.decode('utf-8', errors='replace') for p in parts if p]
                command = ' '.join(parts)
            except ValueError:
                return
        else:
            pt_match = re.search(r'proctitle="([^"]+)"', line)
            if pt_match:
                command = pt_match.group(1)
            else:
                return

        self._proctitles[msg_id] = command

        if msg_id in self._pending:
            self._pending[msg_id]["proctitle"] = command
            if self._pending[msg_id].get("ready"):
                self._attempt_correlation(msg_id)




  


