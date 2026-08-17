import logging
import os
import signal
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from typing import Optional

_AGENT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _AGENT_ROOT not in sys.path :
    sys.path.insert (0, _AGENT_ROOT)

import config
import db
from audit_router import AuditRouter

_IMPORT_ERRORS:dict[str,str]={}

try:
    from fs_monitor.fs_monitor import FSMonitor
except Exception as e:
    FSMonitor = None
    _IMPORT_ERRORS["fs_monitor"] = str(e)

try:
    from net_monitor.net_monitor import NetMonitor
except Exception as e:
    NetMonitor = None
    _IMPORT_ERRORS["net_monitor"] = str(e)

try:
    from usb_monitor.usb_monitor import USBMonitor
except Exception as e:
    USBMonitor = None
    _IMPORT_ERRORS["usb_monitor"] = str(e)

try:
    from screen_monitor.screen_monitor import ScreenMonitor
except Exception as e:
    ScreenMonitor = None
    _IMPORT_ERRORS["screen_monitor"] = str(e)

try:
    from precursor_detector.precursor_detector import PrecursorDetector
except Exception as e:
    PrecursorDetector = None
    _IMPORT_ERRORS["precursor_detector"] = str(e)
 
log = logging.getLogger("agent")

class Agent:

    def __init__ (self):
        self._router: AuditRouter= None
        self._monitors: list[tuple]=[]
        self._crash_history: dict = {}
        self._permanently_failed: set = set()
        self._stop_event = threading.Event()
        self._watchdog_stop = threading.Event()
        self._watchdog_thread: Optional[threading.Thread] =None

    def start(self):
        _setup_logging()
        log.info("=" * 60)
        log.info("Insider Threat Detection Agent starting")
        log.info("=" * 60)

        for name, err in _IMPORT_ERRORS.items():
            log.error("Failed to import %s: %s", name, err)

        _check_pid_file()        
    
        db.init()

        db.replay_overflow()

        db.start_writer()

        log.info("Running initial DB cleanup ..")
        db.cleanup_db()

        self._router= AuditRouter(
            audit_log_path=config.AUDIT_LOG_PATH,
            batch_ms=config.AUDIT_BATCH_MS,
            poll_ms=config.AUDIT_POLL_MS,
            monitored_uids=config.MONITORED_UIDS,
        )

        self._start_all_monitors()
        self._router.start()
        log.info("AuditRouter started — single log reader active")

        _write_pid_file()

        self._start_watchdog()

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self._verify_startup()

        db.write_event("AGENT_EVENT", {
            "event": "AGENT_STARTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "monitors": [name for name, _, _ in self._monitors],
        }
        )
        log.info("Agent fully started — %d monitors running", len(self._monitors))

        self._stop_event.wait()

    def _start_all_monitors(self):

        candidates=[
            ("fs_monitor", FSMonitor ,{"router":self._router}),
            ("net_monitor", NetMonitor, {"router":self._router}),
            ("usb_monitor", USBMonitor, {}),
            ("screen_monitor", ScreenMonitor, {"router":self._router}),
            ("precursor_detector", PrecursorDetector, {"router":self._router}),
        ]

        for name, MonitorClass, kwargs in candidates :
            if MonitorClass is None:
                log.warning("Skipping %s — import failed", name)
                continue
            try:
                instance = MonitorClass(**kwargs)
                thread = threading.Thread(
                    target = self._run_monitor_safe,
                    args = (instance, name),
                    daemon = True,
                    name=name,
                )   
                thread.start()
                self._monitors.append((name,instance,thread))
                log.info("Started monitor: %s", name)
            except Exception as e:
                log.error("Failed to instantiate %s: %s", name, e)
                db.write_event("AGENT_EVENT",{
                        "event": "AGENT_MONITOR_INIT_FAILED",
                        "monitor": name,
                        "error": str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    ) 

    def _run_monitor_safe(self,monitor,name: str):
        try:
            monitor.start()
            log.info("Monitor %s exited normally (no exception)", name)
        except Exception as e:
            tb = traceback.format_exc()
            log.critical("Monitor %s crashed: %s\n%s", name, e, tb)
            db.write_event("AGENT_EVENT_CRASH",{
                "event": "AGENT_MONITOR_CRASH",
                "monitor": name,
                "error": str(e),
                "traceback":tb,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })                    

    def _start_watchdog(self):
        self._watchdog_stop.clear()
        self._watchdog_thread= threading.Thread(
            target=self._watchdog_loop,
            daemon=True,
            name="watchdog",
        )
        self._watchdog_thread.start()
        log.info("Watchdog started (interval=%ds)", config.WATCHDOG_INTERVAL)

    def _watchdog_loop (self):
        while not self._watchdog_stop.is_set():
            self._watchdog_stop.wait(timeout=config.WATCHDOG_INTERVAL)
            if self._watchdog_stop.is_set():
                break

            if not db.is_writer_alive():
                log.critical("DB writer thread died - restarting agent")
                db.write_event("AGENT_EVENt",
                {
                    "event": "AGENT_WRITER_DIED",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                self._handle_signal(signal.SIGTERM,None)
                return
            updated_monitors =[]
            for name, instance, thread in self._monitors:
                if name in self._permanently_failed:
                    continue
                if thread.is_alive():
                    updated_monitors.append((name, instance, thread))
                    continue
                log.warning("Monitor %s died — attempting restart", name)
                new_thread =self._try_restart_(name, instance)
                if new_thread: updated_monitors.append((name,instance, new_thread))
            self._monitors=updated_monitors

    def _try_restart_(self, name: str, instance) -> Optional[threading.Thread]:
        now= time.time()                                
        if name not in self._crash_history:
            self._crash_history[name]=[]
        self._crash_history[name].append(now)
        self._crash_history[name]=[
            t for t in self._crash_history[name]
            if now -t <= config.RESTART_WINDOW
        ]   
        crash_count = len(self._crash_history[name])
        if crash_count > config.MAX_RESTARTS:
            log.critical("Monitor %s exceeded restart limit — giving up", name)
            self._permanently_failed.add(name)
            db.write_event("AGENT_EVENT", {
                "event": "AGENT_MONITOR_FAILED_PERMANENTLY",
                "monitor": name,
                "crash_count": crash_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return None
        backoff = [5,15,30][min(crash_count -1, 2)]
        log.info("Restarting %s in %ds (crash %d/%d)",name, backoff, crash_count, config.MAX_RESTARTS)    
        time.sleep(backoff)

        new_thread= threading.Thread(
            target=self._run_monitor_safe,
            args=(instance, name),
            name=name,
            daemon=True,
        ) 
        new_thread.start()
        db.write_event("AGENT_EVENT",{
            "event": "AGENT_MONITOR_RESTARTED",
            "monitor": name,
            "crash_count": crash_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return new_thread
        

    def _handle_signal(self, signum, frame):
        log.info ("Signal %s received — stopping", signum) 
        threading.Thread(target=self.stop, daemon=True).start()

    def stop(self):
        log.info("Agent stopping ...") 
        db.write_event("AGENT_EVENT",{
            "event": "AGENT_STOPPED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }) 
        self._watchdog_stop.set()
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=5)

        for name, instance, thread in self._monitors:
            try:
                log.info("stopping %s...", name)
                instance.stop()
                thread.join(timeout=10) 
                if thread.is_alive():
                    log.warning(" %s did not stop ", name )
            except Exception as e :
                    log.warning("error stopping %s: %s", name,e)

        log.info("Flushing event queue...")
        db.stop_writer(timeout=30)
        _delete_pid_file()
        self._stop_event.set()
        log.info("AGENT stopped") 

    def _verify_startup(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            if all(t.is_alive()for _, _, t in self._monitors) :
                return 
            time.sleep(0.2)
        for name, _, thread in self._monitors:
            if not thread.is_alive():
                log.critical("Monitor %s failed to start within 10s", name)           
                db.write_event("AGENT_EVENT",{
                    "event": "AGENT_START_FAILED",
                    "monitor": name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

def _setup_logging():
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("watchdog").setLevel(logging.WARNING)
    logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)
 
 
def _check_pid_file():
    if not os.path.exists(config.PID_FILE):
        return
    try:
        with open(config.PID_FILE) as f:
            old_pid = int(f.read().strip())
        os.kill(old_pid, 0)
        log.error("Agent already running (PID %d) — exiting", old_pid)
        sys.exit(1)
    except (ValueError, OSError):
        log.warning("Stale PID file found — removing")
        _delete_pid_file()
 
 
def _write_pid_file():
    pid_dir = os.path.dirname(config.PID_FILE)
    if pid_dir:
        os.makedirs(pid_dir, exist_ok=True)
    with open(config.PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def _delete_pid_file():
    try:
        os.remove(config.PID_FILE)
    except OSError:
        pass


def main():
    agent = Agent()
    agent.start()
 
 
if __name__ == "__main__":
    main()
                                                    