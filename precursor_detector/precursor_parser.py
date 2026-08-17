import  re 
import os
import pwd
import logging
from typing import Optional

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import precursor_detector.config as config

log = logging.getLogger("precursor_parser")

RE_MSG_ID = re.compile(r'audit\((\d+\.\d+):(\d+)\)')
RE_KV     = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')

SYSCALL_NUMBERS = {
    "59":  "execve",
    "105": "setuid",
    "106": "setgid",
    "113": "setreuid",
    "114": "setregid",
    "117": "setresuid",
    "119": "setresgid",
    "126": "capset",

    "90":  "chmod",
    "91":  "fchmod",
    "268": "fchmodat",

    "2":   "open",
    "257": "openat",
}

def _parse_kv(line:str) -> dict :
    result={}
    for match in RE_KV.finditer(line):

        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = value
    return result 
def _extract_msg_id(line:str) -> Optional[str]:
    match = RE_MSG_ID.search(line)
    return f"{match.group(1)}:{match.group(2)}" if match else None

def _resolve_syscall(value: str) -> str:

    return SYSCALL_NUMBERS.get(value, value)

def _resolve_uid (uid_str: str) :
    try : 
        return pwd.getpwuid(int(uid_str)).pw_name
    except (KeyError, ValueError, TypeError):
        return uid_str

def _is_suid_set(a2_hex:str) -> bool:
    try:
        mode = int(a2_hex, 16)
        return bool(mode & 0o4000) or bool(mode & 0o2000)
    except (ValueError, TypeError):
        return False

def _classify_encryption_intent(args: list[str]) -> str:
    args_set = set(args)
    if args_set & config.ENCRYPT_FLAGS:
        return "encrypt"
    if args_set & config.DECRYPT_FLAGS:
        return "decrypt"
    if args and args[0] in ("enc", "smime", "cms", "rsautl", "pkeyutl"):
        return "encrypt"
    if args and args[0] in ("dec",):
        return "decrypt"

    return "unknown"

def parse_syscall_line(line:str) -> Optional [dict]:
    if "type=SYSCALL" not in line: 
        return None

    has_key = any(f'key="{k}"' in line for k in config.AUDIT_KEYS)
    if not has_key :
        return None

    msg_id = _extract_msg_id(line)
    if not msg_id :
        return None

    Kv = _parse_kv(line)

    syscall = Kv.get("SYSCALL") or _resolve_syscall(Kv.get("syscall", "")) 
    if not syscall:
        return None

    uid = Kv.get("uid", "")
    username = _resolve_uid(uid)

    key =""
    for k in config.AUDIT_KEYS:
        if f'key="{k}"' in line :
            key = k
            break 
    return {
    
    "msg_id": msg_id,
    "syscall" : syscall,
    "success": Kv.get("success", "yes"),
    "pid" : Kv.get("pid"),
    "ppid" : Kv.get("ppid"),
    "uid" : uid ,
    "username" : username,
    "euid" : Kv.get("euid"),
    "auid" : Kv.get("auid"),
    "exe" : Kv.get("exe"),
    "comm" : Kv.get("comm"),
    "tty" : Kv.get("tty"),
    "a0":       Kv.get("a0", ""),
    "a1":       Kv.get("a1", ""),
    "a2":       Kv.get("a2", ""),
    "a3":       Kv.get("a3", ""),
    "key":      key,
    "timestamp": msg_id.split(":")[0],

    }   

def parse_execve_line(line: str) -> Optional[dict]:

    if "type=EXECVE" not in line:
        return None

    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None

    Kv = _parse_kv(line)
    argc = int(Kv.get("argc", "0"))
    args = []

    for i in range (argc):
        arg = Kv.get(f"a{i}","")    
        if (arg and len(arg) > 2 and len (arg) % 2== 0 and all(c in "0123456789abcdefABCDEF" for c in arg)) :
            try:
                arg = bytes.fromhex(arg).decode("utf-8", errors="replace")
            except ValueError : 
                pass 
        args.append(arg)

    return {"msg_id": msg_id, "args": args}


                      
def parse_path_line(line:str) -> Optional[dict]:

    if "type=PATH" not in line :
        return None 
    msg_id = _extract_msg_id(line)
    if not msg_id:
        return None

    Kv = _parse_kv(line)
    try :
        item = int(Kv.get("item","1"))
    except ValueError:
        item = 1 

    if item !=0:
        return None

    return{
        "msg_id": msg_id,
        "path" : Kv.get("name"),
        "inode" : Kv.get("inode"),
    }   

def correlate (syscall_data:dict, execve_data:Optional[dict], path_data: Optional[dict]) -> Optional[dict]:

    exe = syscall_data.get("exe","")
    syscall = syscall_data.get("syscall","")
    path = path_data.get("path") if path_data else None
    args = execve_data.get("args", []) if execve_data else []
    category = None
    details = {}

    if (exe == "/usr/bin/sudo" or exe =="/bin/sudo") and syscall == "execve" :
        category ="sudo_execution"
        sudo_arg = args[1] if len(args) > 1 else ""
        details = {
            "sudo_arg": sudo_arg,
            "full_command": " ".join(args)
        }

    elif syscall in ("chmod", "fchmod", "fchmodat"):    
        a2 = syscall_data.get("a2", "")
        if _is_suid_set(a2):
            category = "suid_set"
            try:
                mode_int = int(a2, 16)
                mode_oct = oct(mode_int)

            except (ValueError, TypeError):
                mode_int = 0
                mode_oct = "unknown"

            details = {
                "path": path,
                "mode_hex": a2,
                "mode_oct": mode_oct,
                "suid": bool(mode_int & 0o4000 ),
                "sgid": bool (mode_int & 0o2000 ),
            } 
        else :
            return None      



    elif syscall == "capset":
        BENIGN_CAPSET = {
           "firefox", "chrome", "chromium", "code", "electron"
        }
        exe_name = os.path.basename(exe) if exe else ""
        if any(b in exe for b in BENIGN_CAPSET):
            return None
        category = "capability_change"
        details  = {
        "cap_data_a1": syscall_data.get("a1"),
        "cap_data_a2": syscall_data.get("a2"),
        }           



    elif syscall in ("setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"):
        category = "privilege_escalation"
        target_uid = syscall_data.get("a0", "")
        try:
            target_int= int(target_uid, 16)
            target_name = _resolve_uid(str(target_int)) if target_int < 65535 else "unchanged" 

        except (ValueError, TypeError):
            target_name = target_uid

        pid  = syscall_data.get("pid", "")
        ppid = syscall_data.get("ppid", "")
        
        

        details = {
            "target_uid": target_uid,
            "target_name": target_name,
            "becoming_root": target_uid in ("0", "00000000"),
            "is_sudo_internal": exe in ("/usr/bin/sudo", "/bin/sudo"),
            "sudo_command": syscall_data.get("_sudo_command", "unknown")

        }     
    elif path and any(path.startswith(sf) for sf in config.SENSITIVE_FILES):
        category = "shadow_access"
        a2 = syscall_data.get("a2", "0")
        try:
            flags =int(a2, 16)
            access_type = "write" if (flags & 0x1 or flags & 0x2 ) else "read" 
        except (ValueError, TypeError):
            access_type = "unknown"

        details = {
            "path": path,
            "access_type": access_type,
            "open_flags": a2,
        }   

    elif exe in config.ENCRYPTION_TOOLS:
        category = "encryption_tool"
        intent = _classify_encryption_intent(args[1:] if args else [])
        details = {
            "tool": os.path.basename(exe),
            "intent": intent,
            "arguments": " ".join(args),
            "output_file": _find_output_file(args),

        } 

       
    if not category :
        return None

    return {
        "category":  category,
        "timestamp": syscall_data.get("timestamp"),
        "syscall":   syscall,
        "exe":       exe,
        "path":      path,
        "pid":       syscall_data.get("pid"),
        "ppid":      syscall_data.get("ppid"),
        "uid":       syscall_data.get("uid"),
        "username":  syscall_data.get("username"),
        "euid":      syscall_data.get("euid"),
        "auid":      syscall_data.get("auid"),
        "tty":       syscall_data.get("tty"),
        "success":   syscall_data.get("success"),
        "details":   details,

    }
def _find_output_file (args: list[str]) -> Optional [str]:
    for i, arg in enumerate(args):
        if arg in ("-o", "--output", "-out") and i+1 < len(args):
         return args [i+1] 
    for arg in args :
        if not arg.startswith("-") and "." in arg :
            return arg

    return None      



                    






















