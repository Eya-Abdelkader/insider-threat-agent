import time
import logging
from typing import Optional
 
import sys
import os
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import usb_monitor.config as config 
log = logging.getLogger("mount_resolver")
 
 
class MountResolver:
   
    def wait_for_mount(self, device_node: str) -> Optional[str]:
       
        start = time.time()
        log.info("Attente montage %s (timeout=%ss)...",
                 device_node, config.MOUNT_WAIT_TIMEOUT)
 
        while time.time() - start < config.MOUNT_WAIT_TIMEOUT:
            mount_point = self._read_proc_mounts(device_node)
            if mount_point:
                log.info("Monté : %s → %s (%.1fs)",
                         device_node, mount_point, time.time() - start)
                return mount_point
            time.sleep(config.MOUNT_POLL_INTERVAL)
 
        log.warning("Timeout : %s non monté après %ss",
                    device_node, config.MOUNT_WAIT_TIMEOUT)
        return None
 
    @staticmethod
    def _read_proc_mounts(device_node: str) -> Optional[str]:
       
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == device_node:
                        return parts[1]
        except OSError as e:
            log.warning("Lecture /proc/mounts échouée : %s", e)
        return None
 