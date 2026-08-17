import sys
import os
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

from config import (
    DB_PATH,
    AUDIT_LOG_PATH,
    AUDIT_BATCH_MS,
    AUDIT_POLL_MS,
    LOG_LEVEL,
    SCREEN_TOOL_NAMES,
    SCREEN_SEARCH_DIRS,
    SCREENSHOT_TOOLS,
    RECORDING_TOOLS,
)

AUDIT_KEY = "screen_monitor"

TOOL_NAMES  = SCREEN_TOOL_NAMES
SEARCH_DIRS = SCREEN_SEARCH_DIRS