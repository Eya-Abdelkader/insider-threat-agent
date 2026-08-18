import os as _os 
import logging
import pwd 

try:
    import yaml 
    _YAML_AVAILABLE = True
except ImportError :
    _YAML_AVAILABLE = False

log = logging.getLogger ("config")

CONFIG_FILE = _os.path.join(
    _os.path.dirname(_os.path.abspath(__file__)),
    "config.yaml"
)

_DEFAULTS = {

    "db_path":  "/var/agent/events.db",
    "pid_file":  "/var/agent/agent.pid",
    "overflow_file" : "/var/agent/overflow.jsonl",
    "log_level" : "INFO",

    "baseline_db_path": "/var/agent/baseline.db",

    "db_retention_days" : 3,
    "db_max_size_mb" : 200,
    "db_cleanup_events" : 5000,

    "queue_overflow_limit" : 10000,
    "overflow_max_events" : 1000,

    "watchdog_interval" : 5,
    "max_restarts" : 3,
    "restart_window" : 60,

    "audit_log_path" : "/var/log/audit/audit.log",
    "audit_batch_ms" : 100,
    "audit_poll_ms" : 50,

    "monitored_users": [],

    "watched_paths": ["/home", "/etc", "/var/log", "/tmp", "/usr/local"],
    "sensitive_extensions": [".pdf", ".docx", ".xlsx", ".csv", ".sql", ".db", ".sqlite", ".key", ".pem", ".env", ".json", ".xml", ".bak", ".dump", ".tar", ".zip", ".gz", ".7z", ],

    "mount_wait_timeout": 10, 
    "mount_poll_interval": 0.5,
    "session_inactivity_timeout": 30,

    "ignored_listen_ports": [53, 68, 631, 5353],

    "screen_tool_names": [ "gnome-screenshot", "gnome-screen-recorder", "scrot", "flameshot", "spectacle", "xfce4-screenshooter", "kazam", "obs", "obs-studio", "recordmydesktop", "ffmpeg", "import", "xwd",],

    "screen_search_dirs":[],

    "precursor_audit_keys" : [
        "precursor_priv", "precursor_file", "precursor_crypt" ],

    "encryption_tools":[ "/usr/bin/gpg", "/usr/bin/gpg2", "/usr/bin/openssl", "/usr/bin/zip", "/usr/bin/7z", "/usr/bin/7zr", "/usr/bin/age", "/usr/local/bin/age",],
    "sensitive_files": ["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", ],    

}

def _load_yaml() -> dict :
    if not _YAML_AVAILABLE :
        log.warning ("PyYAML not installed — using all defaults")
        return {}

    if not _os.path.exists (CONFIG_FILE):
        log.info ("Config file not found at %s — using defaults", CONFIG_FILE)
        return {}

    try:
        with open (CONFIG_FILE, "r") as f :
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}

    except (OSError, yaml.YAMLError) as e :
        log.error ("Failed to load config file: %s — using defaults", e)
        return {}

def _build_config() -> dict:
    cfg = dict (_DEFAULTS)
    cfg.update(_load_yaml())
    return cfg

def _resolve_search_dirs ( dirs_from_config: list) -> list:

    _STANDARD_DIRS = ["/usr/bin", "/usr/local/bin", "/bin", "/snap/bin", "/usr/games", "/usr/local/games",] 

    if dirs_from_config:
        return dirs_from_config

    path_dirs = _os.environ.get("PATH", "").split(":")
    path_dirs = [d for d in path_dirs if d]

    combined = list(dict.fromkeys(path_dirs + _STANDARD_DIRS))
    return combined

_CFG = _build_config()


def get (key: str, default=None):
    return _CFG.get(key, default)


    


DB_PATH  = _CFG["db_path"]
PID_FILE = _CFG["pid_file"]
OVERFLOW_FILE = _CFG["overflow_file"]
LOG_LEVEL = _CFG["log_level"]


BASELINE_DB_PATH = _CFG["baseline_db_path"]

DB_RETENTION_DAYS = _CFG["db_retention_days"]
DB_MAX_SIZE_MB = _CFG["db_max_size_mb"]
DB_CLEANUP_EVENTS = _CFG["db_cleanup_events"]

QUEUE_OVERFLOW_LIMIT = _CFG["queue_overflow_limit"]
OVERFLOW_MAX_EVENTS = _CFG["overflow_max_events"]

WATCHDOG_INTERVAL = _CFG["watchdog_interval"]
MAX_RESTARTS = _CFG["max_restarts"]
RESTART_WINDOW = _CFG["restart_window"]

AUDIT_LOG_PATH = _CFG["audit_log_path"]
AUDIT_BATCH_MS = _CFG["audit_batch_ms"]
AUDIT_POLL_MS = _CFG["audit_poll_ms"]

MONITORED_USERS = _CFG["monitored_users"]
MONITORED_UIDS = set()
for _uname in MONITORED_USERS:
    try:
        MONITORED_UIDS.add(pwd.getpwnam(_uname).pw_uid)
    except KeyError:
        log.warning("monitored_users entry '%s' has no matching local account", _uname)    

WATCHED_PATHS = _CFG["watched_paths"]
SENSITIVE_EXTENSIONS  = set(_CFG["sensitive_extensions"])

MOUNT_WAIT_TIMEOUT = _CFG["mount_wait_timeout"]
MOUNT_POLL_INTERVAL        = _CFG["mount_poll_interval"] 
SESSION_INACTIVITY_TIMEOUT = _CFG["session_inactivity_timeout"]

IGNORED_LISTEN_PORTS  = set(_CFG["ignored_listen_ports"])

SCREEN_TOOL_NAMES  = set(_CFG["screen_tool_names"])
SCREEN_SEARCH_DIRS = _resolve_search_dirs(_CFG["screen_search_dirs"])

PRECURSOR_AUDIT_KEYS  = set(_CFG["precursor_audit_keys"])
ENCRYPTION_TOOLS      = set(_CFG["encryption_tools"])
SENSITIVE_FILES       = set(_CFG["sensitive_files"])
 
IGNORED_EXECUTABLES = {
    "/usr/libexec/tracker-extract-3",
    "/usr/libexec/tracker-miner-fs-3",
    "/usr/libexec/tracker-writeback-3",
    "/usr/libexec/gvfsd",
    "/usr/libexec/gvfsd-fuse",
    "/usr/libexec/gvfs-udisks2-volume-monitor",
    "/usr/libexec/xdg-desktop-portal",
    "/usr/libexec/xdg-document-portal",
    "/usr/libexec/gvfs-goa-volume-monitor",
    "/usr/bin/pipewire",           
    "/usr/bin/pipewire-pulse",     
    "/usr/bin/wireplumber", 
    "/snap/firefox/",

    "/usr/lib/systemd/systemd-resolved",
    "/lib/systemd/systemd-resolved",

    "/usr/share/code/code",
    "/snap/code/current/usr/share/code/code",

    "/usr/sbin/NetworkManager",
    "/usr/sbin/NetworkManager",
    "/usr/lib/NetworkManager/nm-dhcp-client.action",
    "/usr/lib/NetworkManager/nm-dispatcher",
}
 
SCREENSHOT_TOOLS = {
    "gnome-screenshot", "scrot", "flameshot",
    "spectacle", "xfce4-screenshooter", "xwd", "import",
}
 
RECORDING_TOOLS = {
    "gnome-screen-recorder", "kazam", "obs", "obs-studio",
    "recordmydesktop", "ffmpeg",
}
 
ENCRYPT_FLAGS = {"-c", "--symmetric", "-e", "--encrypt", "-P", "-p"}
DECRYPT_FLAGS = {"-d", "--decrypt"}







