import os
import logging
import socket
from typing import Optional

import psutil

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import net_monitor.config as config
log = logging.getLogger("connection_builder")


def _get_interface_for_ip(local_ip: str) -> Optional[str]:
    
   
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address == local_ip:
                    return iface
    except Exception:
        pass
    return None


def _get_local_address(pid: str, remote_ip: str,
                       remote_port: int) -> tuple[Optional[str], Optional[int]]:
   
    if not pid:
        return None, None

    try:
        remote_hex_port = format(remote_port, '04X')

        tcp_path = f"/proc/{pid}/net/tcp"
        if os.path.exists(tcp_path):
            packed = socket.inet_aton(remote_ip)
            le_hex = ''.join(f'{b:02X}' for b in reversed(packed))
            remote_pattern = f"{le_hex}:{remote_hex_port}"

            with open(tcp_path, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    if parts[2] == remote_pattern:
                        local = parts[1]
                        local_ip_hex, local_port_hex = local.split(':')
                        local_ip_bytes = bytes(
                            int(local_ip_hex[i:i+2], 16)
                            for i in range(0, 8, 2)
                        )
                        local_ip   = socket.inet_ntoa(bytes(reversed(local_ip_bytes)))
                        local_port = int(local_port_hex, 16)
                        return local_ip, local_port

    except (OSError, ValueError, AttributeError):
        pass

    return None, None


def _determine_direction(syscall: str) -> str:
    
    mapping = {
        "connect":  "outgoing",      
        "accept":   "incoming",      
        "accept4":  "incoming",
        "bind":     "bind",          
        "sendto":   "udp_outgoing",  
        "recvfrom": "udp_incoming",  
    }
    return mapping.get(syscall, "unknown")


def enrich(event: dict) -> Optional[dict]:
    
    exe = event.get("exe")
    ip  = event.get("ip", "")

    if exe in config.IGNORED_EXECUTABLES:
        return None

    if ip.startswith("127.") or ip == "::1":
        return None

    syscall   = event.get("syscall", "")
    direction = _determine_direction(syscall)

    local_ip, local_port = _get_local_address(
        event.get("pid"), ip, event.get("port", 0)
    )


    interface = None
    if local_ip:
        interface = _get_interface_for_ip(local_ip)

    return {
    "event":      event.get("event"),
    "success":    event.get("success"),
    "ip":         event.get("ip"),
    "port":       event.get("port"),
    "family":     event.get("family"),
    "pid":        event.get("pid"),
    "ppid":       event.get("ppid"),
    "uid":        event.get("uid"),
    "username":   event.get("username"),
    "exe":        exe,
    "comm":       event.get("comm"),
    "timestamp":  event.get("timestamp"),
    "direction":  direction,
    "local_ip":   local_ip,
    "local_port": local_port,
    "interface":  interface,
    }