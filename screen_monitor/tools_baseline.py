import os
import logging
from typing import Optional
 
import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import screen_monitor.config as config
 
log = logging.getLogger("tools_baseline")
 
 
def discover() -> dict[str, str]:

    found: dict[str, str] = {}
 
    for name in config.TOOL_NAMES:
        for directory in config.SEARCH_DIRS:
            path = os.path.join(directory, name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                found[name] = path
                log.debug("Found tool: %s at %s", name, path)
                break  
 
    log.info("Tool discovery: %d/%d tools found on this machine",
             len(found), len(config.TOOL_NAMES))
    return found
 
 
def build() -> tuple[dict[int, str], dict[str, str]]:

    tool_paths: dict[str, str] = discover()
    inode_map:  dict[int, str] = {}
 
    for name, path in tool_paths.items():
        try:
            inode = os.stat(path).st_ino
            inode_map[inode] = path
            log.debug("Indexed inode %d → %s", inode, path)
        except OSError as e:
            log.warning("Cannot stat %s: %s", path, e)
 
    log.info("Inode map built: %d tools indexed", len(inode_map))
    return inode_map, tool_paths
 
 
def classify_action(tool_name: Optional[str]) -> str:

    if not tool_name:
        return "screen_capture"
 
    name = os.path.basename(tool_name)   
 
    if name in config.SCREENSHOT_TOOLS:
        return "screenshot"
    if name in config.RECORDING_TOOLS:
        return "recording"
 
    return "screen_capture"   
 
