
import os
import time
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, Callable
import pwd
import subprocess
 
import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import db
import usb_monitor.config as config

 
log = logging.getLogger("transfer_session")

 
class TransferSession:
  
 
    def __init__(self,
                 device_node: str,
                 device_info: dict,
                 mount_point: str,
                 on_closed: Optional[Callable[[str], None]] = None,
                 ):
 
        self.device_node = device_node
        self.device_info = device_info
        self.mount_point = mount_point
        self._on_closed  = on_closed
        
 
        self.session_id  = f"usb_{int(time.time())}_{os.getpid()}"
        self.start_time  = datetime.now(timezone.utc).isoformat()
        self.files: list = []
        self.total_bytes = 0
        self._closed     = False
 
        self._timer_lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._reset_inactivity_timer()
 
        log.info("Session créée : %s sur %s", self.session_id, mount_point)
 
 
    def _reset_inactivity_timer(self):
        with self._timer_lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(
                config.SESSION_INACTIVITY_TIMEOUT,
                self._on_inactivity
            )
            self._timer.daemon = True
            self._timer.start()
 
    def _on_inactivity(self):
        log.info("Session %s : inactivité — fermeture automatique",
                 self.session_id)
        self.finalize(reason="inactivity_timeout")


 
 
    def record_file(self, action: str, path: str):
       
        if self._closed:
            return
 
       
        size = 0
        try:
            size = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            pass
 
        _, ext = os.path.splitext(path)
 
        proc_info = _get_process_info(path)
 
        entry = {
            "action":    action,
            "path":      path,
            "extension": ext.lower(),
            "size":      size,
            "pid":       proc_info.get("pid"),
            "exe":       proc_info.get("exe"),
            "uid":       proc_info.get("uid"),
            "auid":      proc_info.get("auid"),
            "username":  proc_info.get("username"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
 
        self.files.append(entry)
        self.total_bytes += size
        log.debug("[%s] %s — %s (%d bytes)",self.session_id, action, path, size)
 
        
 
        self._reset_inactivity_timer()
 
 
    def finalize(self, reason: str = "usb_removed"):
        
        if self._closed:
            return
        self._closed = True
 
        with self._timer_lock:
            if self._timer:
                self._timer.cancel()
 
        self._emit_event(reason)
 
        if self._on_closed:
            self._on_closed(self.device_node)
 
    def _emit_event(self, reason: str):
        
        payload = {
            "session_id":   self.session_id,
            "device_node":  self.device_node,
            "device_info":  self.device_info,
            "mount_point":  self.mount_point,
            "start_time":   self.start_time,
            "end_time":     datetime.now(timezone.utc).isoformat(),
            "close_reason": reason,
            "total_files":  len(self.files),
            "total_bytes":  self.total_bytes,
            "files":        self.files,  
        }
 
        db.write_event("USB_SESSION", payload)
 
        log.info("Événement émis — session=%s fichiers=%d octets=%d raison=%s",
                 self.session_id, len(self.files), self.total_bytes, reason)
 

def _resolve_uid(uid_str: str) -> str:
    try:
        return pwd.getpwuid(int(uid_str)).pw_name
    except (KeyError, ValueError, TypeError):
        return uid_str or "unknown"


def _get_process_info(path: str) -> dict:
  
    try:
        result = subprocess.run(
            ["lsof", "-t", path],
            capture_output=True,
            text=True,
            timeout=2,
        )
        pid = result.stdout.strip().split("\n")[0].strip()
        if not pid:
            return {}

        exe = os.readlink(f"/proc/{pid}/exe")

        uid = None
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = line.split()[1]
                    break

        auid = None
        try:
            with open(f"/proc/{pid}/loginuid") as f:
                auid = f.read().strip()
                if auid == "4294967295":
                    auid = None
        except OSError:
            pass

        return {
            "pid":      pid,
            "exe":      exe,
            "uid":      uid,
            "auid":     auid,
            "username": _resolve_uid(uid),
        }
    except (OSError, subprocess.TimeoutExpired,
            IndexError, ValueError):
        return {}