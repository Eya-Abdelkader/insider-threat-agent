import logging
import os
import signal
import subprocess
import threading
import sys

_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)


import db
import screen_monitor.config as config
import screen_monitor.tools_baseline as tools_baseline
from screen_monitor.screen_watcher import Screen_Watcher   
from audit_router import AuditRouter
 
log = logging.getLogger("screen_monitor")

def _setup_audit_rules(tool_paths: dict[str, str]):

    success = 0
    skipped = 0

    for name, path in tool_paths.items():
        rule = [
            "-a", "always,exit",
            "-F", "arch=b64",
            "-S", "execve",
            "-F", f"exe={path}",
            "-k", config.AUDIT_KEY,
        ]
        try:
            subprocess.run( 
                ["auditctl"] + rule,
                check=True,
                capture_output=True,
            )
            success +=1
        except subprocess.CalledProcessError as e :
            err = e.stderr.decode().strip()
            if "Rule exists" in err:
                success+=1
            elif "No such file" in err:
                skipped +=1
            else:
                log.warning("auditctl failed for %s: %s", path, err)
        except FileNotFoundError :
            log.error("auditctl not found — is auditd installed?")
            return
    log.info("Audit rules ready: %d added, %d skipped", success, skipped)


class ScreenMonitor: 

    def __init__(self, router: AuditRouter):
        self._router = router
        self._inode_map : dict[int, str]={}
        self._watcher: Screen_Watcher=None
        self._stop_event = threading.Event()

    def start (self):
        inode_map, tool_paths= tools_baseline.build()
        self._inode_map = inode_map   
        log.info("Discovered %d tools, indexed %d inodes",
            len(tool_paths), len(inode_map))
 
        _setup_audit_rules(tool_paths) 

        self._watcher= Screen_Watcher( 
            on_event = self.on_screen_event,
            inode_map=self._inode_map,
            tool_paths=tool_paths,
            router = self._router,
            )
        self._watcher.start()
        log.info("ScreenMonitor started")
        self._stop_event.wait()
        
    def stop(self):
        if self._watcher:
            self._watcher.stop()
        self._stop_event.set()    
        log.info("ScreenMonitor stopped")

    def on_screen_event(self, event:dict):

        log.info(
            "SCREEN_CAPTURE: %s via %s (method=%s output=%s user=%s)",
            event.get("action"),
            event.get("exe"),
            event.get("detection_method"),
            event.get("output_path", "unknown"),
            event.get("username"),
            )
        if event.get("detection_method") == "inode_match":
            log.warning("Renamed tool detected: %s is actually %s",
                event.get("exe"),
                event.get("matched_tool"),)

        db.write_event("SCREEN_CAPTURE", event)

if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
)


    db.init()
    db.start_writer()
    monitor = ScreenMonitor()
    monitor.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        log.info("Ctrl+C — stopping...")
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        monitor.stop()
        db.stop_writer()
        log.info("Stopped.")










