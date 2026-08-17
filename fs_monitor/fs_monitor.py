import logging
import os
import signal
import subprocess
import threading
from datetime import datetime, timezone


import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import db
import fs_monitor.config as config
import fs_monitor.baseline_scanner as baseline_scanner
from fs_monitor.audit_parser   import IGNORED_PATH_COMPONENTS
from fs_monitor.audit_watcher  import AuditWatcher
from fs_monitor.create_watcher import CreateWatcher
from audit_router import AuditRouter

log = logging.getLogger("fs_monitor")



logging.getLogger("watchdog").setLevel(logging.WARNING)
logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)

def _setup_audit_rules():
   
    log.info("Configuration des règles auditctl sur %d chemins...",
             len(config.WATCHED_PATHS))
    success = 0
    failed  = 0

    for path in config.WATCHED_PATHS:
        if not os.path.exists(path):
            log.warning("Chemin introuvable, règle ignorée : %s", path)
            continue
        try:
            subprocess.run(
                ["auditctl", "-w", path, "-p", "rwxa",
                 "-k", config.AUDIT_KEY],
                check=True,
                capture_output=True,
            )
            log.debug("Règle auditctl ajoutée : %s", path)
            success += 1
        except subprocess.CalledProcessError as e:
            log.warning("auditctl échec pour %s : %s",
                        path, e.stderr.decode().strip())
            failed += 1
        except FileNotFoundError:
            log.error("auditctl introuvable — auditd est-il installé ?")
            return
    for path in baseline_scanner.CRITICAL_SYSTEM_FILES:
        if not os.path.exists(path):
            log.warning("Chemin introuvable, règle ignorée : %s", path)
            continue
        try:
            subprocess.run(
                ["auditctl", "-w", path, "-p", "rwa",
                 "-k", config.AUDIT_KEY],
                check=True,
                capture_output=True,
            )
            log.debug("Règle auditctl ajoutée (fichier critique) : %s", path)
            success += 1
        except subprocess.CalledProcessError as e:
            log.warning("auditctl échec pour %s : %s",
                        path, e.stderr.decode().strip())
            failed += 1
        except FileNotFoundError:
            log.error("auditctl introuvable — auditd est-il installé ?")
            return


    log.info("Règles auditctl : %d succès, %d échecs", success, failed)




class FSMonitor:
    def __init__(self, router:AuditRouter):
        self._router = router
        self._baseline: set = set()
        self._audit_watcher: AuditWatcher  = None
        self._create_watcher: CreateWatcher = None
        self._lock          = threading.Lock()
        self._recent_processes: dict = {}
        self._recent_lock = threading.Lock()

    def start(self):
       
        baseline_scanner.init_baseline_db()
        log.info("Scan du filesystem au démarrage...")
        self._baseline = baseline_scanner.scan()
        log.info("Baseline : %d fichiers sensibles", len(self._baseline))

        _setup_audit_rules()

        self._audit_watcher = AuditWatcher(
            on_event=self.on_audit_event,
            router=self._router
        )
        self._audit_watcher.start()

        self._create_watcher = CreateWatcher(
            on_event=self.on_watchdog_event,
            baseline=self._baseline,
        )
        self._create_watcher.start()

        log.info("FSMonitor démarré.")
        threading.Event().wait()



    def on_audit_event(self, event: dict):
        
        path = event.get("path", "")

        agent_dir = os.path.dirname(os.path.abspath(__file__))
        if path.startswith(agent_dir) or path == config.DB_PATH:
            return

        if any(component in path for component in IGNORED_PATH_COMPONENTS):
            return

        with self._lock:
            if path not in self._baseline:
                return

        log.info("Événement FS : %s → %s (pid=%s user=%s exe=%s)",
                 event.get("action"), path,
                 event.get("pid"), event.get("username"), event.get("exe"))

        with self._recent_lock:
            self._recent_processes[path] = {
                "pid":      event.get("pid"),
                "ppid":     event.get("ppid"),
                "uid":      event.get("uid"),
                "username": event.get("username"),
                "exe":      event.get("exe"),
                "comm":     event.get("comm"),
            }

        db.write_event("FS_ACCESS", event)

    def on_watchdog_event(self, path: str, action: str, extra: dict):
        
        log.info("Événement watchdog : %s → %s", action, path)

        with self._recent_lock:
            proc = self._recent_processes.get(path, {})

        payload = {
            "path":      path,
            "action":    action,
            "pid":       proc.get("pid"),
            "ppid":      proc.get("ppid"),
            "uid":       proc.get("uid"),
            "username":  proc.get("username"),
            "exe":       proc.get("exe"),
            "comm":      proc.get("comm"),
            "timestamp": datetime.now(timezone.utc).timestamp(),
            "enriched_from_cache": proc != {},
        }

        if action == "moved" and extra.get("dest_path"):
            payload["dest_path"] = extra["dest_path"]

        if action == "deleted":
            with self._recent_lock:
                self._recent_processes.pop(path, None)

        db.write_event("FS_ACCESS", payload)

    

    def stop(self):
        log.info("Arrêt FSMonitor...")

        if self._audit_watcher:
            try:
                self._audit_watcher.stop()
            except Exception as e:
                log.warning("Erreur arrêt audit_watcher : %s", e)

        if self._create_watcher:
            try:
                self._create_watcher.stop()
            except Exception as e:
                log.warning("Erreur arrêt create_watcher : %s", e)

        log.info("FSMonitor arrêté.")




if __name__ == "__main__":

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
)
    db.init()
    db.start_writer()    
    monitor = FSMonitor()
    monitor.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        log.info("Ctrl+C reçu — arrêt...")
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        monitor.stop()
        db.stop_writer()
        log.info("Arrêt complet.")