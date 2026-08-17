import pwd
import re
import logging
from typing import Optional

IGNORED_EXECUTABLES = {
    "/usr/libexec/tracker-extract-3",
    "/usr/libexec/tracker-miner-fs-3",
    "/usr/bin/tracker",
    "/usr/libexec/gvfsd",
    "/usr/libexec/gvfs-udisks2-volume-monitor",
    "/usr/lib/gnome-online-accounts/goa-daemon",
    "/usr/libexec/xdg-desktop-portal",
    "/usr/libexec/xdg-document-portal",
    "/usr/share/code/code",
    "/usr/bin/code",
    "/snap/code/current/usr/share/code/code",
}

IGNORED_PATH_COMPONENTS = {
    ".config", ".cache", ".local/share/recently-used",
    ".vscode", "snap/code", "snap/firefox",
    "Code/User/History", "Code/User/workspaceStorage",
    "/.mozilla/", "/Cache/",
}

log = logging.getLogger("audit_parser")

RE_MSG_ID  = re.compile(r'audit\((\d+\.\d+):(\d+)\)')

RE_KV      = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')

SYSCALL_TO_ACTION = {
    "openat":     "opened",
    "open":       "opened",
    "read":       "accessed",
    "write":      "modified",
    "close_write":"modified",
    "unlink":     "deleted",
    "unlinkat":   "deleted",
    "rename":     "moved",
    "renameat":   "moved",
    "renameat2":  "moved",
    "close":      "closed",
    "chmod":      "attr_changed",
    "fchmod":     "attr_changed",
    "fchmodat":   "attr_changed",
    "chown":      "attr_changed",
    "fchown":     "attr_changed",
    "fchownat":   "attr_changed",
    "lchown":     "attr_changed",
}


SYSCALL_NUMBERS = {
    "0":   "read",
    "1":   "write",
    "2":   "open",
    "3":   "close",
    "82":  "rename",
    "87":  "unlink",
    "90":  "chmod",
    "91":  "chown",
    "92":  "lchown",
    "93":  "fchmod",
    "94":  "fchown",
    "257": "openat",
    "259": "renameat",
    "260": "fchownat",
    "261": "futimesat",
    "263": "unlinkat",
    "268": "fchmodat",
    "316": "renameat2",
}


def _resolve_syscall(value: str) -> str:
    return SYSCALL_NUMBERS.get(value, None)


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


def parse_syscall_line(line: str) -> Optional[dict]:
   
    if "type=SYSCALL" not in line:
        return None

    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None

    kv = _parse_kv(line)

    syscall = _resolve_syscall(kv.get("syscall", ""))
    action  = SYSCALL_TO_ACTION.get(syscall)
    
    if  not action :
        return None

    if kv.get("success") == "no":
        return None

    exe = kv.get("exe")

    if exe in IGNORED_EXECUTABLES:
        return None

    
    if action == "opened":
        a2 = kv.get("a2", "")
        write_flags = {"O_WRONLY", "O_RDWR", "O_WRONLY|O_CREAT",
                       "O_WRONLY|O_APPEND", "O_RDWR|O_CREAT",
                       "O_WRONLY|O_CREAT|O_TRUNC", "O_WRONLY|O_CREAT|O_APPEND"}
        try:
            a2_int = int(a2, 16) if a2.startswith("0x") else int(a2)
            if a2_int & 0x3 in (1, 2):
                action = "modified"
        except (ValueError, TypeError):
            if any(flag in a2 for flag in ("O_WRONLY", "O_RDWR")):
                action = "modified"

    uid      = kv.get("uid")
    username = None
    if uid:
        try:
            username = pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError):
            username = uid   

    return {
        "msg_id":   msg_id,
        "syscall":  syscall,
        "action":   action,
        "pid":      kv.get("pid"),
        "ppid":     kv.get("ppid"),
        "uid":      uid,
        "username": username,
        "auid": kv.get("auid"),
        "exe":      exe,
        "comm":     kv.get("comm"),
        "success":  kv.get("success"),
        "open_flags": kv.get("a2"),   
    }


def parse_cwd_line(line: str) -> Optional[dict]:
   
    if "type=CWD" not in line:
        return None
    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None
    kv  = _parse_kv(line)
    cwd = kv.get("cwd")
    if not cwd:
        return None
    return {"msg_id": msg_id, "cwd": cwd}


def parse_proctitle_line(line: str) -> Optional[dict]:
  
    if "type=PROCTITLE" not in line:
        return None
    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None
    kv        = _parse_kv(line)
    proctitle = kv.get("proctitle", "")
    parts = proctitle.split()
    if len(parts) >= 2:
        return {"msg_id": msg_id, "proctitle": proctitle, "arg": parts[-1]}
    return None


def parse_path_line(line: str) -> Optional[dict]:
    
    if "type=PATH" not in line:
        return None

    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None

    kv   = _parse_kv(line)
    path = kv.get("name")

    if not path or path in {".", ".."}:
        return None

    try:
        item = int(kv.get("item", "0"))
    except ValueError:
        item = 0

    return {
        "msg_id": msg_id,
        "path":   path,
        "item":   item,
    }


def correlate(syscall_data: dict, path_data: dict) -> Optional[dict]:
   
    if syscall_data["msg_id"] != path_data["msg_id"]:
        return None

    timestamp = syscall_data["msg_id"].split(":")[0]

    return {
        "path":       path_data["path"],
        "action":     syscall_data["action"],
        "pid":        syscall_data.get("pid"),
        "ppid":       syscall_data.get("ppid"),
        "uid":        syscall_data.get("uid"),
        "username":   syscall_data.get("username"),
        "auid":              syscall_data.get("auid"),
        "exe":        syscall_data.get("exe"),
        "comm":       syscall_data.get("comm"),
        "open_flags": syscall_data.get("open_flags"),
        "timestamp":  timestamp,
    }