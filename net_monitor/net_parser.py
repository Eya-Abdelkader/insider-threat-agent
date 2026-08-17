

import re
import os 
import pwd
import socket
import struct
import logging
from typing import Optional


import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import net_monitor.config as config

log = logging.getLogger("net_parser")


RE_MSG_ID = re.compile(r'audit\((\d+\.\d+):(\d+)\)')

RE_KV = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')

SYSCALL_NUMBERS = {
    "42":  "connect",
    "43":  "accept",
    "49":  "bind",
    "288": "accept4",
    "44":  "sendto",    
    "45":  "recvfrom",  
}

SYSCALL_TO_EVENT = {
    "connect":  "CONNECTION_ATTEMPT",   
    "accept":   "CONNECTION_INCOMING",  
    "accept4":  "CONNECTION_INCOMING",  
    "bind":     "PORT_BIND",            
    "sendto":   "UDP_SEND",             
    "recvfrom": "UDP_RECEIVE",          
}

def _parse_kv(line: str) -> dict:

    result = {}
    for match in RE_KV.finditer(line):
        key   = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = value
    return result


def _extract_msg_id(line: str) -> Optional[str]:
    
    match = RE_MSG_ID.search(line)
    return f"{match.group(1)}:{match.group(2)}" if match else None


def _resolve_syscall(value: str) -> str:
    return SYSCALL_NUMBERS.get(value, value)


def _decode_saddr(saddr_hex: str) -> Optional[dict]:

    try:
        if len(saddr_hex) < 16:
            return None

        raw    = bytes.fromhex(saddr_hex[:16])
        family = struct.unpack("<H", raw[0:2])[0]

        if family == 2:    
            port = struct.unpack(">H", raw[2:4])[0]  
            ip   = socket.inet_ntoa(raw[4:8])
            return {"ip": ip, "port": port, "family": "IPv4"}

        elif family == 10:  #
            if len(saddr_hex) < 56:
                return None
            raw6 = bytes.fromhex(saddr_hex[:56])
            port = struct.unpack(">H", raw6[2:4])[0]
            ip   = socket.inet_ntop(socket.AF_INET6, raw6[8:24])
            return {"ip": ip, "port": port, "family": "IPv6"}

        return None

    except (ValueError, struct.error, OSError):
        return None


def _resolve_uid(uid_str: str) -> str:
   
    try:
        return pwd.getpwuid(int(uid_str)).pw_name
    except (KeyError, ValueError, TypeError):
        return uid_str



def parse_syscall_line(line: str) -> Optional[dict]:
  
    if "type=SYSCALL" not in line:
        return None

    if f'key="{config.AUDIT_KEY}"' not in line:
        return None

    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None

    kv      = _parse_kv(line)
    syscall = _resolve_syscall(kv.get("syscall", ""))
    event   = SYSCALL_TO_EVENT.get(syscall)

    if not event:
        return None

    uid      = kv.get("uid", "")
    username = _resolve_uid(uid)

    return {
        "msg_id":    msg_id,
        "event":     event,
        "syscall":   syscall,
        "success":   kv.get("success", "yes"),
        "pid":       kv.get("pid"),
        "ppid":      kv.get("ppid"),
        "uid":       uid,
        "username":  username,
        "auid": kv.get("auid"),
        "exe":       kv.get("exe"),
        "comm":      kv.get("comm"),
        "timestamp": msg_id.split(":")[0],
    }


def parse_sockaddr_line(line: str) -> Optional[dict]:
   
    if "type=SOCKADDR" not in line:
        return None

    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None

    kv    = _parse_kv(line)
    saddr = kv.get("saddr", "")

    addr = _decode_saddr(saddr)
    if not addr:
        return None

    return {
        "msg_id": msg_id,
        "ip":     addr["ip"],
        "port":   addr["port"],
        "family": addr["family"],
    }


def correlate(syscall_data: dict, sockaddr_data: dict) -> Optional[dict]:
   
    if syscall_data["msg_id"] != sockaddr_data["msg_id"]:
        return None

    return {
        "event":     syscall_data["event"],
        "syscall":   syscall_data["syscall"],
        "success":   syscall_data["success"],
        "ip":        sockaddr_data["ip"],
        "port":      sockaddr_data["port"],
        "family":    sockaddr_data["family"],
        "pid":       syscall_data["pid"],
        "ppid":      syscall_data["ppid"],
        "uid":       syscall_data["uid"],
        "username":  syscall_data["username"],
        "auid":              syscall_data.get("auid"),
        "exe":       syscall_data["exe"],
        "comm":      syscall_data["comm"],
        "timestamp": syscall_data["timestamp"],
    }