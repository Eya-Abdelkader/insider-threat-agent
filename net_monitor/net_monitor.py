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

import net_monitor.config as config
from net_monitor.connection_builder import enrich
from net_monitor.net_audit_watcher   import NetAuditWatcher
from net_monitor.port_baseline       import PortBaseline
from net_monitor.connection_aggregator import ConnectionAggregator
from audit_router import AuditRouter

log = logging.getLogger("net_monitor")



def _setup_audit_rules():
   
    rules = [
        ["-a", "always,exit", "-F", "arch=b64", "-S", "connect",
         "-k", config.AUDIT_KEY],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "accept",
         "-k", config.AUDIT_KEY],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "accept4",
         "-k", config.AUDIT_KEY],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "bind",
         "-k", config.AUDIT_KEY],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "sendto",
         "-F", "a2!=0", "-k", config.AUDIT_KEY],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "recvfrom",
         "-F", "a2!=0", "-k", config.AUDIT_KEY],
    ]

    success = 0
    for rule in rules:
        try:
            subprocess.run(
                ["auditctl"] + rule,
                check=True,
                capture_output=True,
            )
            success += 1
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode().strip()
            if "Rule exists" in err:
                success += 1  
            else:
                log.warning("auditctl rule failed: %s — %s",
                            " ".join(rule[5:]), err)
        except FileNotFoundError:
            log.error("auditctl not found — is auditd installed?")
            return

    log.info("Audit rules ready: %d/%d", success, len(rules))




class NetMonitor:
    

    def __init__(self, router: AuditRouter):
        self._router = router
        self._baseline = PortBaseline()
        self._aggregator = ConnectionAggregator()
        self._watcher  = NetAuditWatcher(on_event=self.on_net_event, router = router)
        self._stop_event = threading.Event()

    def start(self):
        _setup_audit_rules()
        self._baseline.build()
        self._aggregator.start()
        self._watcher.start()
        log.info("NetMonitor started — listening for network events via auditd")
        self._stop_event.wait()

    def stop(self):
        self._watcher.stop()
        self._aggregator.stop()
        self._stop_event.set()
        log.info("NetMonitor stopped")

    def on_net_event(self, event: dict):
        event_type = event.get("event", "")

        if event_type == "PORT_BIND":
            port_events = self._baseline.process_bind(event)
            for pe in port_events:
                db.write_event("PORT_EVENT", pe)
                log.info("PORT_EVENT: %s port %s on %s (exe=%s)",
                         pe.get("event_type"),
                         pe.get("port"),
                         pe.get("listening_on"),
                         pe.get("exe"))
            return

        enriched = enrich(event)
        if enriched is None:
            return   

        log.debug("%s: %s→%s:%s (exe=%s success=%s)",
                 event_type,
                 enriched.get("local_ip", "?"),
                 enriched.get("ip"),
                 enriched.get("port"),
                 enriched.get("exe"),
                 enriched.get("success"))

        self._aggregator.process(enriched)




if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
    )
    db.init()
    db.start_writer()

    from audit_router import AuditRouter
    router = AuditRouter(
        audit_log_path=config.AUDIT_LOG_PATH,
        batch_ms=config.AUDIT_BATCH_MS,
        poll_ms=config.AUDIT_POLL_MS,
    )

    monitor = NetMonitor(router)
    router.start()

    try:
        monitor.start()   
    except KeyboardInterrupt:
        log.info("Ctrl+C — stopping...")
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        monitor.stop()
        router.stop()
        db.stop_writer()
        log.info("Stopped.")