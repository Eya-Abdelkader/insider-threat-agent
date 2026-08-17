import logging
import threading
import subprocess
import os
import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)
 
import db
import pyudev
import usb_monitor.config as config
from usb_monitor.mount_resolver   import MountResolver
from usb_monitor.transfer_session import TransferSession
from usb_monitor.file_watcher     import USBFileWatcher
 

 
log = logging.getLogger("usb_monitor")
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
)
 
 
class USBMonitor:
   
 
    def __init__(self):
        self._resolver = MountResolver()
        self._active: dict[str, tuple[TransferSession, USBFileWatcher]] = {}
        self._lock = threading.Lock()
 
 
    def _on_device_added(self, device):
        device_node = device.device_node
        device_info = {
            "id_vendor": device.get("ID_VENDOR",  "unknown"),
            "id_model":  device.get("ID_MODEL",   "unknown"),
            "id_serial": device.get("ID_SERIAL",  "unknown"),
        }
 
        log.info("USB inséré : %s (%s %s)",
                 device_node, device_info["id_vendor"], device_info["id_model"])
 
        db.write_event("USB_INSERTED", {"device": device_node, **device_info})
 
        t = threading.Thread(
            target=self._setup_session,
            args=(device_node, device_info),
            daemon=True,
            name=f"usb-setup-{device_node.replace('/', '_')}",
        )
        t.start()
 
    def _setup_session(self, device_node: str, device_info: dict):
        mount_point = self._resolver.wait_for_mount(device_node)
        if mount_point is None:
            log.error("Session annulée — montage introuvable pour %s", device_node)
            return

        try:
            subprocess.run(
            ["auditctl", "-w", mount_point, "-p", "rwxa",
             "-k", "usb_access"],
            capture_output=True, check=True,
            )
            log.info("auditd rule added for USB mount: %s", mount_point)
        except subprocess.CalledProcessError as e:
            log.warning("auditctl failed for %s: %s",mount_point, e.stderr.decode().strip())
        except FileNotFoundError:
            log.error("auditctl not found")            

    
 
        session = TransferSession(
            device_node=device_node,
            device_info=device_info,
            mount_point=mount_point,
            on_closed=self._on_session_closed,
        )
 
        watcher = USBFileWatcher(session, mount_point)
        watcher.start()
 
        with self._lock:
            self._active[device_node] = (session, watcher)
 
 
    def _on_device_removed(self, device):
        device_node = device.device_node
        log.info("USB retiré : %s", device_node)
 
        db.write_event("USB_REMOVED", {"device": device_node})
 
        with self._lock:
            entry = self._active.get(device_node)
 
        if entry:
            session, watcher = entry
            try:
                subprocess.run(
                    ["auditctl", "-W", session.mount_point, "-p", "rwxa",
                    "-k", "usb_access"],
                    capture_output=True, check=True,
             )
                log.info("auditd rule removed for: %s", session.mount_point)
            except subprocess.CalledProcessError:
                pass
            except FileNotFoundError:
                pass


            watcher.stop()
            session.finalize(reason="usb_removed")
 
    def _on_session_closed(self, device_node: str):
       
        with self._lock:
            entry = self._active.pop(device_node, None)
        if entry:
            _, watcher = entry
            if watcher._observer.is_alive():
                watcher.stop()
 
 
    def start(self):
        self._stop_event = threading.Event()
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="block")
        monitor.start()
        log.info("USBMonitor démarré — écoute udev...")
 
        while not self._stop_event.is_set():
            device = monitor.poll(timeout=1)
            if device is None:
                continue

            if device.get("DEVTYPE") != "partition":
                continue
            if device.action == "add":
                self._on_device_added(device)
            elif device.action == "remove":
                self._on_device_removed(device)
 
    def stop(self):
        log.info("Arrêt USBMonitor...")
        if hasattr(self, '_stop_event'):
            self._stop_event.set()
        with self._lock:
            items = list(self._active.items())
        for device_node, (session, watcher) in items:
            watcher.stop()
            session.finalize(reason="agent_shutdown")
        log.info("USBMonitor arrêté.")
 
 
 
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
    )

    db.init()
    db.start_writer()
    monitor = USBMonitor()
    try:
        monitor.start()
    except KeyboardInterrupt:
        log.info("Arrêt demandé...")
    finally:
        monitor.stop()
        db.stop_writer()
 