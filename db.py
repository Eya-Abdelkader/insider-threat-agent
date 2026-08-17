import json 
import logging
import os
import queue 
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Optional
import config

log = logging.getLogger("db")

_write_queue:   queue.Queue              = queue.Queue()
_queue_size:    int                      = 0
_queue_lock                              = threading.Lock()
_writer_thread: Optional[threading.Thread] = None
_stop_event                              = threading.Event()
_event_counter: int                      = 0
_counter_lock                            = threading.Lock()

def init():

    db_dir = os.path.dirname(config.DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS event_queue (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            type      TEXT    NOT NULL,
            payload   TEXT    NOT NULL,
            sent      INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    log.info("Database initialised at %s (WAL mode)", config.DB_PATH)


def replay_overflow():

    if not os.path.exists(config.OVERFLOW_FILE):
        return

    replayed= 0
    try:
        with open(config.OVERFLOW_FILE, "r") as f :
            for line in f :
                line = line.strip()
                if not line :
                    continue
                try:
                    event = json.loads(line)
                    _write_queue.put_nowait((event.get("type", "UNKNOWN"), event.get("payload", {}))) 
                    replayed +=1   
                except (json.JSONDecodeError, Exception):
                    continue

        os.remove(config.OVERFLOW_FILE)
        log.info("Replayed %d events from overflow file", replayed)
    except OSError as e:
        log.error("Failed to replay overflow file: %s", e)

def start_writer():

    global _writer_thread
    _stop_event.clear()
    _writer_thread= threading.Thread(
        target= _writer_loop,
        daemon= True,
        name= "db-writer",
    )
    _writer_thread.start()
    log.info("DB writer thread started")

def _writer_loop():
    batch = []
    while True:
        try:
            item = _write_queue.get(timeout=0.5)
        except queue.Empty:
            if batch:
                _flush_batch(batch)
                batch = []
            continue

        if item == (None, None):
            if batch:
                _flush_batch(batch)
            log.info("DB writer thread stopping")
            return

        batch.append(item)

        while len(batch) < 50:
            try:
                item = _write_queue.get_nowait()
                if item == (None, None):
                    _flush_batch(batch)
                    log.info("DB writer thread stopping")
                    return
                batch.append(item)
            except queue.Empty:
                break

        if batch:
            _flush_batch(batch)
            batch = []
def _flush_batch(batch: list):

    global _queue_size
    now = datetime.now(timezone.utc).isoformat()
 
    try:
        conn = sqlite3.connect(config.DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        with conn:
            conn.executemany(
                "INSERT INTO event_queue (timestamp, type, payload) VALUES (?,?,?)",
                [
                    (now, event_type, json.dumps(payload))
                    for event_type, payload in batch
                ]
            )
        conn.close()
 
        with _queue_lock:
            _queue_size = max(0, _queue_size - len(batch))
 
    except sqlite3.Error as e:
        log.error("DB batch write failed (%d events): %s", len(batch), e)
        for event_type, payload in batch:
            _write_overflow(event_type, payload)

def write_event(event_type: str, payload: dict):

    global _queue_size, _event_counter
 
    with _queue_lock:
        current_size = _queue_size
 
    if current_size >= config.QUEUE_OVERFLOW_LIMIT:
        _write_overflow(event_type, payload)
        return
 
    _write_queue.put_nowait((event_type, payload))
 
    with _queue_lock:
        _queue_size += 1
 
    with _counter_lock:
        _event_counter += 1
        if _event_counter >= config.DB_CLEANUP_EVENTS:
            _event_counter = 0
            _trigger_cleanup()
           

def stop_writer(timeout: float = 30.0):
    _write_queue.put_nowait((None, None))

    if _writer_thread and _writer_thread.is_alive():
        _writer_thread.join(timeout=timeout)
        if _writer_thread.is_alive():
            log.warning("Writer thread timed out — draining to overflow")
            _drain_queue_to_overflow()


def is_writer_alive() -> bool:
    return _writer_thread is not None and _writer_thread.is_alive()



def _write_overflow(event_type: str, payload: dict):
    overflow_dir= os.path.dirname(config.OVERFLOW_FILE)
    if overflow_dir:
        os.makedirs(overflow_dir, exist_ok= True)

    try:
        record = {
            "type": event_type,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }   

        with open(config.OVERFLOW_FILE, "a") as f:
            f.write(json.dumps(record)+ "\n")

        with open(config.OVERFLOW_FILE, "r") as f :
            line_count = sum(1 for _ in f)

        if line_count >= config.OVERFLOW_MAX_EVENTS:
            log.critical("Overflow reached %d events", line_count)
            _write_critical_direct({
                "event": "AGENT_OVERFLOW_CRITICAL",
                "overflow_count": line_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })                         

    except OSError as e :
        log.critical("Cannont write to overflow file: %s", e)


def _write_critical_direct(payload: dict):

    try:
        conn= sqlite3.connect(config.DB_PATH, timeout=5)
        conn.execute(
            "INSERT INTO event_queue (timestamp, type, payload) VALUES (?,?,?)",
            (
                datetime.now(timezone.utc).isoformat(),
                "AGENT_EVENT",
                json.dumps(payload),
            )
        ) 
        conn.commit()
        conn.close()
    except sqlite3.Error as e :
        log.critical("Emergency direct write failed: %s", e)

def _drain_queue_to_overflow():
    drained = 0
    while True:
        try:
            item  = _write_queue.get_nowait()
            if item == (None, None):
                break
            event_type, payload= item
            _write_overflow(event_type, payload)
            drained +=1

        except queue.Empty:
            break
    if drained:
        log.warning("Drained %d events to overflow during shutdown", drained)


def cleanup_db():
    try:
        conn = sqlite3.connect(config.DB_PATH, timeout=10)
 
        conn.execute("""
            DELETE FROM event_queue
            WHERE sent = 1
              AND timestamp < datetime('now', ? || ' days')
        """, (f"-{config.DB_RETENTION_DAYS}",))
 
        conn.commit()
        db_size_mb = os.path.getsize(config.DB_PATH) / (1024 * 1024)
 
        if db_size_mb > config.DB_MAX_SIZE_MB:
            conn.execute("""
                DELETE FROM event_queue
                WHERE id IN (
                    SELECT id FROM event_queue
                    WHERE sent = 1
                    ORDER BY id ASC
                    LIMIT 5000
                )
            """)
            conn.commit()
            conn.execute("VACUUM")
            conn.commit()
            log.info("DB cleanup: vacuumed (was %.1fMB)", db_size_mb)
        else:
            log.debug("DB cleanup done (%.1fMB)", db_size_mb)
 
        conn.close()
 
    except sqlite3.Error as e:
        log.error("DB cleanup failed: %s", e)

def _trigger_cleanup():
    t= threading.Thread(target= cleanup_db, daemon= True, name="db-cleanup")
    t.start()
    



        




