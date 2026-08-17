import sys
import os
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)


_dir = os.path.dirname(os.path.abspath(__file__))
while _dir != "/" and not os.path.exists(os.path.join(_dir, "db.py")):
    _dir = os.path.dirname(_dir)

if _dir not in sys.path:
    sys.path.insert(0, _dir)    

from config import (
    DB_PATH,
    AUDIT_LOG_PATH,
    AUDIT_BATCH_MS,
    AUDIT_POLL_MS,
    IGNORED_LISTEN_PORTS,
    IGNORED_EXECUTABLES,
    LOG_LEVEL,
)

AUDIT_KEY = "net_monitor"