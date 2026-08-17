import os
import subprocess
import logging
from pathlib import Path
from typing import Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import fs_monitor.config as config

IGNORED_DIRS = {
    ".config", ".cache", ".mozilla",
    "snap", ".vscode", ".vscode-server",
    "proc", "sys", "dev", "run",
}

ALWAYS_WATCH = {
    "Trash", "files",   
}

log = logging.getLogger("create_watcher")


class _CreateOnlyHandler(FileSystemEventHandler):
   
    def __init__(self,
                 on_event: Callable[[str, str, dict], None],
                 baseline: set):
        super().__init__()
        self._on_event = on_event
        self._baseline = baseline

    def on_created(self, event):
        if event.is_directory:
            return

        path  = event.src_path
        parts = Path(path).parts

        if any(p in IGNORED_DIRS for p in parts):
            return

        _, ext = os.path.splitext(path)
        if ext.lower() not in config.SENSITIVE_EXTENSIONS:
            return

        self._baseline.add(path)
        log.info("Nouveau fichier sensible détecté : %s", path)
        self._on_event(path, "created", {})

    def on_deleted(self, event):
        if event.is_directory:
            return

        path  = event.src_path
        parts = Path(path).parts

        if any(p in IGNORED_DIRS for p in parts):
            return

        _, ext = os.path.splitext(path)
        if ext.lower() not in config.SENSITIVE_EXTENSIONS:
            return

        self._baseline.discard(path)
        log.info("Fichier supprimé détecté : %s", path)
        self._on_event(path, "deleted", {})

    def on_moved(self, event):
        if event.is_directory:
            return

        src   = event.src_path
        dst   = event.dest_path
        parts = Path(src).parts

        if any(p in IGNORED_DIRS for p in parts):
            return

        _, ext = os.path.splitext(src)
        if ext.lower() not in config.SENSITIVE_EXTENSIONS:
            return

        self._baseline.discard(src)
        _, dst_ext = os.path.splitext(dst)
        if dst_ext.lower() in config.SENSITIVE_EXTENSIONS:
            self._baseline.add(dst)

        log.info("Fichier déplacé : %s → %s", src, dst)
        self._on_event(src, "moved", {"dest_path": dst})

    def on_modified(self, event): pass


def _add_audit_watch(path: str):

    try:
        subprocess.run(
            ["auditctl", "-w", path, "-p", "rwxa",
             "-k", config.AUDIT_KEY],
            check=True,
            capture_output=True,
        )
        log.debug("Règle auditctl ajoutée : %s", path)
    except subprocess.CalledProcessError as e:
        log.warning("Impossible d'ajouter règle auditctl pour %s : %s",
                    path, e.stderr.decode())
    except FileNotFoundError:
        log.error("auditctl introuvable — auditd est-il installé ?")


class CreateWatcher:
    def __init__(self,
                 on_event: Callable[[str, str, dict], None],
                 baseline: set):
        self._baseline = baseline
        handler        = _CreateOnlyHandler(on_event, baseline)
        self._observer = Observer()

        for path in config.WATCHED_PATHS:
            if os.path.exists(path):
                self._observer.schedule(handler, path, recursive=True)
                log.debug("CreateWatcher programmé sur %s", path)

    def start(self):
        self._observer.start()
        log.info("CreateWatcher démarré")

    def stop(self):
        self._observer.stop()
        self._observer.join(timeout=3)
        log.info("CreateWatcher arrêté")

    @property
    def is_alive(self) -> bool:
        return self._observer.is_alive()