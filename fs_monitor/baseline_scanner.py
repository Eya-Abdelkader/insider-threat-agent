import os
import logging
import sqlite3
from datetime import datetime, timezone

import sys
_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import fs_monitor.config as config
log = logging.getLogger("baseline_scanner")


def init_baseline_db(db_path: str = config.BASELINE_DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            path         TEXT    NOT NULL UNIQUE,
            extension    TEXT    NOT NULL,
            size_bytes   INTEGER,
            checksum     TEXT,
            discovered   TEXT    NOT NULL,
            last_seen    TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()


_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))


def scan(db_path: str = config.BASELINE_DB_PATH) -> set:
   
    sensitive_files = set()
    now             = datetime.now(timezone.utc).isoformat()
    conn            = sqlite3.connect(db_path)

    for watched_path in config.WATCHED_PATHS:
        if not os.path.exists(watched_path):
            log.warning("Chemin surveillé introuvable : %s", watched_path)
            continue

        log.info("Scan de %s...", watched_path)
        count = 0

        for root, dirs, files in os.walk(watched_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in {
                "proc", "sys", "dev", "run", "snap"
            }]

            for filename in files:
                filepath = os.path.join(root, filename)
                _, ext   = os.path.splitext(filename)

                if ext.lower() not in config.SENSITIVE_EXTENSIONS:
                    continue

                if filepath.startswith(_AGENT_DIR):
                    continue

                if any(c in filepath for c in {
                    "/.config/", "/.cache/", "/.local/share/recently",
                    "/Code/User/History", "/Code/User/workspaceStorage",
                    "/.mozilla/", "/snap/code/", "/snap/firefox/",
                }):
                    continue

                try:
                    size = os.path.getsize(filepath)
                except OSError:
                    size = None

                conn.execute("""
                    INSERT INTO baseline (path, extension, size_bytes, discovered, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        size_bytes = excluded.size_bytes,
                        last_seen  = excluded.last_seen
                """, (filepath, ext.lower(), size, now, now))

                sensitive_files.add(filepath)
                count += 1

        log.info("Scan terminé : %s — %d fichiers sensibles", watched_path, count)

    conn.commit()
    conn.close()
    log.info("Baseline : %d fichiers sensibles au total", len(sensitive_files))
    return sensitive_files


def load_from_db(db_path: str = config.BASELINE_DB_PATH) -> set:
    try:
        conn  = sqlite3.connect(db_path)
        rows  = conn.execute("SELECT path FROM baseline").fetchall()
        conn.close()
        paths = {row[0] for row in rows}
        log.info("Baseline chargée depuis DB : %d fichiers", len(paths))
        return paths
    except sqlite3.Error as e:
        log.error("Erreur chargement baseline : %s", e)
        return set()