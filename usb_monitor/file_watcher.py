import logging

import os
import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import usb_monitor.config as config

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
 
from usb_monitor.transfer_session import TransferSession
 
log = logging.getLogger("file_watcher")
 
 
class _USBEventHandler(FileSystemEventHandler):
 
    def __init__(self, session: TransferSession):
        super().__init__()
        self._session = session
 
    def on_created(self, event):
        if not event.is_directory:
            self._session.record_file("created", event.src_path)
 
    def on_modified(self, event):
        if not event.is_directory:
            self._session.record_file("modified", event.src_path)
 
    def on_moved(self, event):
        if not event.is_directory:
            self._session.record_file("moved", event.dest_path)
 
 
class USBFileWatcher:
   
 
    def __init__(self, session: TransferSession, mount_point: str):
        self._session     = session
        self._mount_point = mount_point
        self._observer    = Observer()
        self._observer.schedule(
            _USBEventHandler(session),
            mount_point,
            recursive=True
        )
 
    def start(self):
        self._observer.start()
        log.info("Watcher inotify démarré sur %s [session=%s]",
                 self._mount_point, self._session.session_id)
 
    def stop(self):
        self._observer.stop()
        self._observer.join()
        log.info("Watcher inotify arrêté sur %s", self._mount_point)
 