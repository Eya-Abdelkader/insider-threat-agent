import logging
import os
import signal
import subprocess
import threading

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import db
import precursor_detector.config as config
from precursor_detector.precursor_watcher import PrecursorWatcher
from audit_router import AuditRouter

log = logging.getLogger("precursor_detector")


def _set_audit_rules():

    rules = [
        ["-w", "/usr/bin/sudo", "-p", "x", "-k", "precursor_priv"],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "setuid,setgid,setreuid,setregid,setresuid,setresgid",
            "-k", "precursor_priv"
        ],
        [
            "-a", "always,exit", "-F", "arch=b32",
            "-S", "setuid,setgid,setreuid,setregid,setresuid,setresgid",
            "-k", "precursor_priv"
        ],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "capset", 
            "-k", "precursor_priv"
        ],
        [
            "-a", "always,exit" ,"-F", "arch=b32",
            "-S", "capset", "-k", "precursor_priv"
        ],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "chmod,fchmod,fchmodat",
            "-F", "auid>=1000", "-F", "auid!=-1",
            "-k", "precursor_priv"
        ],
        [
            "-a", "always,exit", "-F", "arch=b32",
            "-S", "chmod,fchmod,fchmodat",
            "-F", "auid>=1000", "-F", "auid!=-1",
            "-k", "precursor_priv"
        ],
        [
            "-w", "/etc/shadow", "-p", "rwa", "-k", "precursor_file"
        ],
        [
            "-w", "/etc/gshadow", "-p", "rwa", "-k", "precursor_file"
        ],
        [
            "-w", "/etc/sudoers", "-p", "wa", "-k", "precursor_file"
        ],
        [
            "-w", "/etc/sudoers.d", "-p", "wa", "-k", "precursor_file"
        ],
        [
            "-a", "always,exit", "-F", "arch=b64", 
            "-S", "execve", "-F", "exe=/usr/bin/gpg",
            "-k", "precursor_crypt"
        ],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "execve", "-F", "exe=/usr/bin/gpg2",
            "-k", "precursor_crypt"
        ],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "execve", "-F", "exe=/usr/bin/openssl",
            "-k", "precursor_crypt"
        ],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "execve", "-F", "exe=/usr/bin/zip",
            "-k", "precursor_crypt"

        ],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "execve", "-F", "exe=/usr/bin/7z",
            "-k", "precursor_crypt"            
        ],
        [
            "-a", "always,exit", "-F", "arch=b64",
            "-S", "execve", "-F", "exe=/usr/bin/7za",
            "-k", "precursor_crypt"            
        ],


    ]

    success = 0
    for rule in rules :
        try:
            subprocess.run(
                ["auditctl"] + rule,
                check=True,
                capture_output=True,
            )
            success+=1
        except subprocess.CalledProcessError as e :
            err = e.stderr.decode().strip()
            if "Rule exists" in err :
                success+=1
            elif "No such file" in err :
                pass 
            else :
                log.warning("auditctl failed: %s — %s"," ".join(rule), err)  
        except FileNotFoundError :
            log.error("auditctl not found — is auditd installed?") 
            return
    log.info("Audit rules ready: %d/%d", success, len(rules))

CATEGORY_LABELS = {
    "sudo_execution":      "SUDO EXECUTION",
    "suid_set":            "SUID BIT SET",
    "capability_change":   "CAPABILITY CHANGE",
    "privilege_escalation":"RUNTIME PRIVILEGE CHANGE",
    "shadow_access":       "SENSITIVE FILE ACCESS",
    "encryption_tool":     "ENCRYPTION TOOL INVOKED",
}
class PrecursorDetector:

    def __init__ (self, router: AuditRouter):

        self._router = router
        self._watcher = PrecursorWatcher(on_event=self.on_precursor_event, router = router)
        self._stop_event= threading.Event()

    def start (self):
        
        _set_audit_rules()
        self._watcher.start()
        log.info("PrecursorDetector started — watching for pre-attack signals")
        self._stop_event.wait()
    def stop(self):
        self._watcher.stop()
        self._stop_event.set()
        log.info("PrecursorDetector stopped")

    def on_precursor_event(self, event: dict):

        category = event.get("category", "unknown")
        label    = CATEGORY_LABELS.get(category, category.upper())
        details  = event.get("details", {})
 
        is_high_risk = (
            category in ("suid_set", "shadow_access", "capability_change",
                         "privilege_escalation")
            or details.get("becoming_root") is True
            or details.get("intent") == "encrypt"
        )
 
        msg = (
            f"{label} | "
            f"user={event.get('username')} "
            f"auid={event.get('auid')} " 
            f"exe={event.get('exe')} "
            f"pid={event.get('pid')} "
            f"success={event.get('success')}"
        )
 
        if category == "sudo_execution":
            msg += f" | command={details.get('full_command')}"

        elif category == "privilege_escalation":
            msg += (
            f" | target_user={details.get('target_name')} "
            f"becoming_root={details.get('becoming_root')} "
            f"command={details.get('sudo_command', 'unknown')}"  
        )


        elif category == "suid_set":
            msg += f" | path={details.get('path')} mode={details.get('mode_oct')}"
        elif category == "shadow_access":
            msg += f" | path={details.get('path')} access={details.get('access_type')}"
        elif category == "encryption_tool":
            msg += f" | tool={details.get('tool')} intent={details.get('intent')}"
 
        if is_high_risk:
            log.warning(msg)
        else:
            log.info(msg)

        db.write_event("PRECURSOR_EVENT", event)
          


if __name__ == "__main__":

    logging.basicConfig(
        level = getattr(logging, config.LOG_LEVEL),
        format = "%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
    db.init()
    db.start_writer()

    from audit_router import AuditRouter
    router = AuditRouter(
        audit_log_path=config.AUDIT_LOG_PATH,
        batch_ms=config.AUDIT_BATCH_MS,
        poll_ms=config.AUDIT_POLL_MS,
    )

    detector = PrecursorDetector(router)
    router.start()
    
    try:
        detector.start()
        
    except KeyboardInterrupt:
        log.info("Ctrl+C — stopping...")
    finally:    
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        detector.stop()
        router.stop()
        db.stop_writer()
        log.info("Stopped.")

        











            
