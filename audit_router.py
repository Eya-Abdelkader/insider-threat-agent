import os
import re
import time
import logging
import threading
from typing import Callable, Optional
 
log = logging.getLogger("audit_router")
 
RE_MSG_ID = re.compile(r'audit\((\d+\.\d+):(\d+)\)')
RE_KEY    = re.compile(r'key="([^"]+)"')
RE_AUID   = re.compile(r'\bauid=(\d+)\b')

_KEYED_TYPES = {"type=SYSCALL"}

_CORRELATED_TYPES = {"type=EXECVE", "type=PATH", "type=SOCKADDR",
                     "type=CWD", "type=EOE", "type=PROCTITLE"}
def _extract_msg_id(line:str) -> Optional[str]:
    m= RE_MSG_ID.search(line)
    return f"{m.group(1)}:{m.group(2)}" if m else None

def _extract_key(line:str)-> Optional[str]:
    m=RE_KEY.search(line)
    return m.group(1) if m else None


def _extract_auid(line: str) -> Optional[int]:
    m = RE_AUID.search(line)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


class AuditRouter:


    def __init__(self, audit_log_path:str, batch_ms:int=100, poll_ms:int=50,
                 monitored_uids: Optional[set] = None):
        self._path = audit_log_path
        self._batch_ms= batch_ms
        self._poll_ms=poll_ms
        self._monitored_uids = monitored_uids or set()

        self._callbacks: dict[str,list[Callable[[str],None]]] ={}

        self._pending_owners:dict[str,set[str]] ={}
        self._owners_lock=threading.Lock()

        self._stop_event= threading.Event()
        self._thread= threading.Thread(
            target=self._run,
            daemon=True,
            name="audit-router",
        )



    def register(self, key:str, callback:Callable[[str], None]) -> None:
        if key not in self._callbacks:
            self._callbacks[key] =[]
        if callback not in self._callbacks[key]:
            self._callbacks[key].append(callback)
        log.debug("Registered callback for key=%s (%s)",
                  key, getattr(callback, "__qualname__", repr(callback)))

    def release_msg_id(self, msg_id:str, key:str) -> None:
        with self._owners_lock:
            owners = self._pending_owners.get(msg_id)
            if owners is None:
                return
            owners.discard(key)
            if not owners:
                del self._pending_owners[msg_id]

    def start(self) -> None:
        self._stop_event.clear()
        self._thread.start()
        log.info("AuditRouter started on %s", self._path)
        if self._monitored_uids:
            log.info("AuditRouter: filtering to %d monitored uid(s)", len(self._monitored_uids))

    def stop (self) -> None:
        self._stop_event.set()
        self._thread.join(timeout=5)
        log.info("AuditRouter stopped")


    def _run(self) -> None:
        f,current_inode= self._open_log()
        if f is None:
            log.error("AuditRouter: cannot open %s — is auditd running?", self._path)
            return
        while not self._stop_event.is_set():
            batch=[]
            deadline = time.time() + self._batch_ms / 1000.0
            while time.time() < deadline:
                line = f.readline()
                if line:
                    batch.append(line)
                else:
                    time.sleep(self._poll_ms / 1000.0)
                    if self._confirm_rotation(current_inode):
                        log.debug("AuditRouter: log rotation confirmed — reopening")
                        f.close()
                        f, current_inode = self._open_log(seek_end=False)
                        if f is None:
                            return
            for line in batch:

                self._dispatch(line.rstrip("\n"))
        f.close()



    def _confirm_rotation(self, current_inode: int, checks: int = 3, interval: float = 0.05) -> bool:
        for _ in range(checks):
            new = self._get_inode()
            if new is None or new == current_inode:
                return False
            time.sleep(interval)
        return True


    def _dispatch(self, line:str) -> None:
        if not line:
            return 
        if "type=SYSCALL" in line :
            key = _extract_key(line)
            if key is None or key not in self._callbacks:
                return

            if self._monitored_uids:
                auid = _extract_auid(line)
                if auid is None or auid not in self._monitored_uids:

                    return

            msg_id = _extract_msg_id(line)
            if msg_id is None:
                return

            with self._owners_lock:
                if msg_id not in self._pending_owners:
                    self._pending_owners[msg_id] = set()
                self._pending_owners[msg_id].add(key)
            for cb in self._callbacks[key]:
                try:
                    cb(line)
                except Exception:
                    log.exception("AuditRouter: callback error (key=%s)", key)
            return
        has_correlated = any(t in line for t in _CORRELATED_TYPES)
        if not has_correlated:
            return
        msg_id = _extract_msg_id(line)
        if msg_id is None:
            return
        with self._owners_lock:
            owners = self._pending_owners.get(msg_id)
            if not owners:
                return
            keys_snapshot=set(owners)
        seen: set[int] =set()
        for key in keys_snapshot:
            for cb in self._callbacks.get(key,[]):
                cb_id= id(cb)
                if cb_id not in seen :
                    seen.add(cb_id)
                    try:
                        cb(line)
                    except Exception:
                        log.exception("AuditRouter: callback error ""(correlated, key=%s)", key)


        self._gc_pending_owners()

    def _gc_pending_owners(self) ->None:

        now= time.time()
        with self._owners_lock:
            if len(self._pending_owners) < 200:
                return 
            stale=[
                mid for mid in list(self._pending_owners)
                if _msg_id_age(mid, now) > 5.0
            ]                       
            for mid in stale :
                del self._pending_owners[mid]
            if stale:
                log.debug("AuditRouter: GC removed %d stale msg_ids",len(stale))

    def _open_log(self, seek_end: bool=True):
        try:
            f = open(self._path, "r")
            inode = os.fstat(f.fileno()).st_ino
            if seek_end:
                f.seek(0,2)
            return f, inode
        except (OSError, PermissionError) as e :
            log.error("AuditRouter: cannot open %s: %s", self._path, e)
            return None, None        

    def _get_inode(self) -> Optional[int]:
        try:
            return os.stat(self._path).st_ino
        except OSError:
            return None

def _msg_id_age(msg_id:str, now:float) -> float:
    try:
        return now - float(msg_id.split(":")[0])
    except (ValueError, IndexError):
        return 0.0