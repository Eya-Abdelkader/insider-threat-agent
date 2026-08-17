import json
import logging
import os
import sqlite3
import ssl 
import sys
import time
import requests
from datetime import datetime, timezone, timedelta

import urllib.request
import urllib.error

_AGENT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _AGENT_ROOT not in sys.path:
    sys.path.insert(0, _AGENT_ROOT)

import config

log = logging.getLogger("sender")

AI_SERVER_URL   = config.get("ai_server_url", "http://localhost:5000/events")
BATCH_SIZE      = config.get("sender_batch_size", 500)
ARCHIVE_AFTER_DAYS = config.get("sender_archive_after_days", 3)
ARCHIVE_DIR     = config.get("sender_archive_dir", "/var/agent/archive")
TIMEOUT_SECONDS = config.get("sender_timeout_seconds", 10)
MTLS_ENABLED =config.get("mtls_enabled", False)
CERT_DIR = config.get("cert_dir", "/opt/agent/certs")

def _build_ssl_context():
    if not  MTLS_ENABLED:
        return None 
    if not AI_SERVER_URL.startswith("https"):
        log.warning(
            "mtls_enabled is true but ai_server_url (%s) isn't https:// -- "
            "mTLS has no effect over plain HTTP. Fix ai_server_url in config.",
            AI_SERVER_URL,

        )  
    ctx= ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)    
    ctx.load_cert_chain(
        certfile=os.path.join(CERT_DIR, "client.crt"),
        keyfile=os.path.join(CERT_DIR, "client.key"),
    )
    ctx.load_verify_locations(cafile=os.path.join(CERT_DIR, "ca.crt"))
    return ctx

_SSL_CONTEXT = _build_ssl_context()    


def _archive_old_events(conn: sqlite3.Connection) -> int:

    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=ARCHIVE_AFTER_DAYS)).isoformat()

    rows = conn.execute("""
        SELECT id, timestamp, type, payload
        FROM event_queue
        WHERE sent = 0 AND timestamp < ?
    """, (cutoff,)).fetchall()

    if not rows:
        return 0

    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    today     = datetime.now().strftime("%Y%m%d")
    archive_path = os.path.join(ARCHIVE_DIR, f"undelivered_{today}.jsonl")

    with open(archive_path, "a") as f:
        for row_id, timestamp, event_type, payload_str in rows:
            record = {
                "id":        row_id,
                "timestamp": timestamp,
                "type":      event_type,
                "payload":   json.loads(payload_str),
                "archived_at": datetime.now(timezone.utc).isoformat(),
            }
            f.write(json.dumps(record) + "\n")

    ids = [row[0] for row in rows]
    conn.execute(
        f"UPDATE event_queue SET sent = 2 WHERE id IN "
        f"({','.join('?' * len(ids))})",
        ids,
    )
    conn.commit()

    log.warning("%d events archived (undelivered after %d days) → %s",
                len(rows), ARCHIVE_AFTER_DAYS, archive_path)
    return len(rows)



def _fetch_pending(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT id, timestamp, type, payload
        FROM event_queue
        WHERE sent = 0
        ORDER BY id ASC
        LIMIT ?
    """, (BATCH_SIZE,)).fetchall()

    events = []
    for row_id, timestamp, event_type, payload_str in rows:
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            payload = {"raw": payload_str}

        events.append({
            "_db_id":    row_id,
            "timestamp": timestamp,
            "type":      event_type,
            "payload":   payload,
        })
    return events



def _mark_sent(conn: sqlite3.Connection, ids: list[int]):
    conn.execute(
        f"UPDATE event_queue SET sent = 1 WHERE id IN "
        f"({','.join('?' * len(ids))})",
        ids,
    )
    conn.commit()



def _post_events(events: list[dict]) -> bool:

    payload = [
        {k: v for k, v in e.items() if k != "_db_id"}
        for e in events
    ]

    body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        AI_SERVER_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Host":  os.uname().nodename,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                log.info("Delivered %d events → %s", len(events), AI_SERVER_URL)
                return True
            else:
                log.warning("AI server returned HTTP %d", resp.status)
                return False

    except urllib.error.URLError as e:
        log.warning("Cannot reach AI server (%s): %s", AI_SERVER_URL, e.reason)
        return False
    except Exception as e:
        log.warning("POST failed: %s", e)
        return False


 

def run_once():

    if not os.path.exists(config.DB_PATH):
        log.debug("Database not found yet: %s", config.DB_PATH)
        return

    try:
        conn = sqlite3.connect(config.DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error as e:
        log.error("Cannot open database: %s", e)
        return

    try:
        _archive_old_events(conn)

        events = _fetch_pending(conn)
        if not events:
            log.debug("No pending events.")
            return

        log.info("Found %d pending events.", len(events))

        success = _post_events(events)

        if success:
            ids = [e["_db_id"] for e in events]
            _mark_sent(conn, ids)
        else:
            log.info("Events remain pending — will retry next cycle.")

    finally:
        conn.close()


def main():
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    interval = config.get("sender_interval_seconds", 60)
    log.info("Sender started — posting to %s every %ds", AI_SERVER_URL, interval)

    while True:
        try:
            run_once()
        except Exception as e:
            log.error("Unexpected error in sender cycle: %s", e)
        time.sleep(interval)


if __name__ == "__main__":
    main()