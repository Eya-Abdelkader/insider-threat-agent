import re
import pwd
import logging
import os
from typing import Optional
 
import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import screen_monitor.config as config
from screen_monitor.tools_baseline import classify_action
 
log = logging.getLogger("screen_parser")
 

RE_MSG_ID = re.compile(r'audit\((\d+\.\d+):(\d+)\)')
RE_KV     = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')
 
 
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
 
 
def _resolve_uid(uid_str: str) -> str:
    try:
        return pwd.getpwuid(int(uid_str)).pw_name
    except (KeyError, ValueError, TypeError):
        return uid_str
 
 
def _extract_output_path(args: list[str]) -> Optional[str]:
   
    if not args:
        return None
 
    for i, arg in enumerate(args):
        if arg in ("-f", "-o", "--file", "--output") and i + 1 < len(args):
            return args[i + 1]
 
    last = args[-1] if args else None
    if last and not last.startswith("-") and ("." in last or "/" in last):
        return last
 
    return None
 
 
def parse_syscall_line(line: str) -> Optional[dict]:
    
    if "type=SYSCALL" not in line:
        return None
    if f'key="{config.AUDIT_KEY}"' not in line:
        return None
 
    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None
 
    kv = _parse_kv(line)
 
    syscall = kv.get("syscall", "")
    if syscall not in ("execve", "59"):  
        return None
 
    uid      = kv.get("uid", "")
    username = _resolve_uid(uid)
 
    return {
        "msg_id":    msg_id,
        "pid":       kv.get("pid"),
        "ppid":      kv.get("ppid"),
        "uid":       uid,
        "username":  username,
        "auid": kv.get("auid"),
        "exe":       kv.get("exe"),
        "timestamp": msg_id.split(":")[0],
    }
 
 
def parse_execve_line(line: str) -> Optional[dict]:
   
    if "type=EXECVE" not in line:
        return None
 
    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None
 
    kv   = _parse_kv(line)
    argc = int(kv.get("argc", "0"))
    args = []
 
    for i in range(argc):
        arg = kv.get(f"a{i}", "")
        if arg and all(c in "0123456789abcdefABCDEF" for c in arg) and len(arg) % 2 == 0 and len(arg) > 2:
            try:
                arg = bytes.fromhex(arg).decode("utf-8", errors="replace")
            except ValueError:
                pass
        args.append(arg)
 
    return {
        "msg_id": msg_id,
        "args":   args,
    }
 
 
def parse_path_line(line: str) -> Optional[dict]:
    
    if "type=PATH" not in line:
        return None
 
    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None
 
    kv = _parse_kv(line)
 
    try:
        item = int(kv.get("item", "1"))
    except ValueError:
        return None
 
    if item != 0:
        return None
 
    inode_str = kv.get("inode")
    if not inode_str:
        return None
 
    try:
        inode = int(inode_str)
    except ValueError:
        return None
 
    return {
        "msg_id": msg_id,
        "inode":  inode,
        "name":   kv.get("name"),
    }
 
 
def correlate(syscall_data: dict,
              execve_data: Optional[dict],
              path_data: Optional[dict],
              inode_map: dict[int, str],
              tool_paths: Optional[dict[str, str]] = None) -> Optional[dict]:
   
    exe  = syscall_data.get("exe", "")
    args = execve_data.get("args", []) if execve_data else []
 
    known_paths = set(tool_paths.values()) if tool_paths else set()
 
    detection_method = None
    matched_tool     = None
 
    if exe in known_paths:
        detection_method = "exe_match"
        matched_tool     = exe
 
    elif path_data and path_data.get("inode") in inode_map:
        inode            = path_data["inode"]
        detection_method = "inode_match"
        matched_tool     = inode_map[inode]
        log.warning(
            "Renamed screen capture tool detected: %s (inode=%d matches %s)",
            exe, inode, matched_tool
        )
 
    if not detection_method:
        return None   
 
    tool_name   = os.path.basename(matched_tool) if matched_tool else None
    action      = classify_action(tool_name)
    output_path = _extract_output_path(args[1:] if args else [])
 
    return {
        "action":           action,
        "exe":              exe,
        "matched_tool":     matched_tool,
        "tool_name":        tool_name,
        "detection_method": detection_method,
        "command":        " ".join(args),
        "output_path":      output_path,
        "pid":              syscall_data.get("pid"),
        "ppid":             syscall_data.get("ppid"),
        "uid":              syscall_data.get("uid"),
        "auid":              syscall_data.get("auid"),
        "username":         syscall_data.get("username"),
        "timestamp":        syscall_data.get("timestamp"),
    }
 
