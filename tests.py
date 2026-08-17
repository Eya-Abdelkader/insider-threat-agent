
import json
import os
import queue
import sqlite3
import sys
import threading
import time
from unittest.mock import MagicMock, patch


import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "events.db")
    conn    = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE event_queue (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            type      TEXT NOT NULL,
            payload   TEXT NOT NULL,
            sent      INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    return db_path
    



class TestCentralDb:

    def test_write_event_reaches_db(self, tmp_db):
        import db
        import config
        with patch.object(config, "DB_PATH", tmp_db):
            db._write_queue  = queue.Queue()
            db._queue_size   = 0
            db._event_counter = 0
            db._writer_thread = None
            db._stop_event.clear()

            db.init()
            db.start_writer()
            db.write_event("TEST_EVENT", {"key": "value"})
            time.sleep(1)
            db.stop_writer(timeout=5)
            

        rows = sqlite3.connect(tmp_db).execute(
            "SELECT type, payload FROM event_queue"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "TEST_EVENT"
        assert json.loads(rows[0][1])["key"] == "value"

    def test_sent_defaults_to_zero(self, tmp_db):
        import db
        import config
        with patch.object(config, "DB_PATH", tmp_db):
            db._write_queue   = queue.Queue()
            db._queue_size    = 0
            db._event_counter = 0
            db._writer_thread = None
            db._stop_event.clear()

            db.init()
            db.start_writer()
            db.write_event("EVENT", {"x": 1})
            time.sleep(0.3)
            db.stop_writer(timeout=5)

        sent = sqlite3.connect(tmp_db).execute(
            "SELECT sent,COUNT(sent) FROM event_queue"
        ).fetchone() [0]
        assert sent == 0
        

    def test_overflow_written_when_queue_full(self, tmp_path):
        import db
        import config
        overflow = str(tmp_path / "overflow.jsonl")
        with patch.object(config, "QUEUE_OVERFLOW_LIMIT", 0):
            with patch.object(config, "OVERFLOW_FILE", overflow):
                db.write_event("OVERFLOW_TEST", {"data": "x"})

        assert os.path.exists(overflow)
        with open(overflow) as f:
            record = json.loads(f.readline())
        assert record["type"] == "OVERFLOW_TEST"

    def test_replay_overflow_puts_events_in_queue(self, tmp_path, tmp_db):
        import db
        import config
        overflow = str(tmp_path / "overflow.jsonl")

        with open(overflow, "w") as f:
            f.write(json.dumps({"type": "REPLAYED", "payload": {"n": 1}}) + "\n")
            f.write(json.dumps({"type": "REPLAYED", "payload": {"n": 2}}) + "\n")

        with patch.object(config, "DB_PATH", tmp_db):
            with patch.object(config, "OVERFLOW_FILE", overflow):
                db._write_queue   = queue.Queue()
                db._queue_size    = 0
                db._event_counter = 0
                db._writer_thread = None
                db._stop_event.clear()

                db.replay_overflow()
                db.start_writer()
                time.sleep(0.3)
                db.stop_writer(timeout=5)

        assert not os.path.exists(overflow)
        count = sqlite3.connect(tmp_db).execute(
            "SELECT COUNT(*) FROM event_queue WHERE type='REPLAYED'"
        ).fetchone()[0]
        assert count == 2

class TestNetParser:

    def test_decode_ipv4_sockaddr(self):
        from net_monitor.net_parser import _decode_saddr
        result = _decode_saddr("02000\
1BB5DB8D82200000000")
        assert result is not None
        assert result["port"]   == 443
        assert result["ip"]     == "93.184.216.34"
        assert result["family"] == "IPv4"

    def test_decode_unknown_family_returns_none(self):
        from net_monitor.net_parser import _decode_saddr
        result = _decode_saddr("0100" + "00" * 12)
        assert result is None

    def test_parse_syscall_wrong_key_ignored(self):
        from net_monitor.net_parser import parse_syscall_line
        line = (
            'type=SYSCALL msg=audit(1776075351.428:52834): arch=c000003e '
            'syscall=42 success=yes exit=0 ppid=1000 pid=1234 '
            'uid=1000 exe="/usr/bin/curl" key="sensitive_access"'
            'ARCH=x86_64 SYSCALL=connect'
        )
        assert parse_syscall_line(line) is None

    def test_parse_syscall_connect(self):
        from net_monitor.net_parser import parse_syscall_line
        line = (
            'type=SYSCALL msg=audit(1776075351.428:52834): arch=c000003e '
            'syscall=42 success=yes exit=0 ppid=1000 pid=1234 '
            'uid=1000 exe="/usr/bin/curl" key="net_monitor"'
            'ARCH=x86_64 SYSCALL=connect AUID="aya" UID="aya"'
        )
        result = parse_syscall_line(line)
        assert result is not None
        assert result["event"]   == "CONNECTION_ATTEMPT"
        assert result["syscall"] == "connect"
        assert result["exe"]     == "/usr/bin/curl"

    def test_correlate_merges_syscall_and_sockaddr(self):
        from net_monitor.net_parser import correlate
        syscall = {
            "msg_id": "123:1", "event": "CONNECTION_ATTEMPT",
            "syscall": "connect", "success": "yes",
            "pid": "1234", "ppid": "1000",
            "uid": "1000", "username": "aya",
            "exe": "/usr/bin/curl", "comm": "curl",
            "timestamp": "123",
        }
        sockaddr = {
            "msg_id": "123:1",
            "ip": "93.184.216.34", "port": 443, "family": "IPv4",
        }
        result = correlate(syscall, sockaddr)
        assert result is not None
        assert result["ip"]    == "93.184.216.34"
        assert result["port"]  == 443
        assert result["exe"]   == "/usr/bin/curl"

    def test_correlate_mismatched_msg_id_returns_none(self):
        from net_monitor.net_parser import correlate
        syscall  = {"msg_id": "123:1", "event": "CONNECTION_ATTEMPT",
                    "syscall": "connect", "success": "yes",
                    "pid": "1", "ppid": "0", "uid": "0",
                    "username": "root", "exe": "/usr/bin/curl",
                    "comm": "curl", "timestamp": "123"}
        sockaddr = {"msg_id": "123:2", "ip": "1.2.3.4",
                    "port": 80, "family": "IPv4"}
        assert correlate(syscall, sockaddr) is None

class TestAuditParser:

    def _syscall_line(self, syscall="openat", exe="/usr/bin/vim",
                      success="yes", uid="1000",
                      msg_id="1776075351.428:12345",valu=257):
        return (
            f'type=SYSCALL msg=audit({msg_id}): arch=c000003e '
            f'syscall={valu} success={success} exit=3 ppid=1000 pid=2000 '
            f'uid={uid} exe="{exe}" comm="vim" a2=0 '
            f'ARCH=x86_64 SYSCALL={syscall} UID="aya"'
        )

    def _path_line(self, path="/home/aya/secret.pdf",
                   msg_id="1776075351.428:12345"):
        return (
            f'type=PATH msg=audit({msg_id}): item=0 '
            f'name="{path}" inode=123456 dev=08:01'
        )

    def test_parse_syscall_openat(self):
        from fs_monitor.audit_parser import parse_syscall_line
        result = parse_syscall_line(self._syscall_line())
        assert result is not None
        assert result["action"] == "opened"
        assert result["exe"]    == "/usr/bin/vim"

    def test_parse_syscall_failure_ignored(self):
        from fs_monitor.audit_parser import parse_syscall_line
        result = parse_syscall_line(
            self._syscall_line(success="no")
        )
        assert result is None

    def test_parse_syscall_unknown_ignored(self):
        from fs_monitor.audit_parser import parse_syscall_line
        line = self._syscall_line(syscall="mmap",valu=None)
        result = parse_syscall_line(line)
        assert result is None

    def test_parse_path_line(self):
        from fs_monitor.audit_parser import parse_path_line
        result = parse_path_line(self._path_line())
        assert result is not None
        assert result["path"] == "/home/aya/secret.pdf"

    def test_path_dot_ignored(self):
        from fs_monitor.audit_parser import parse_path_line
        line = 'type=PATH msg=audit(123:1): item=0 name="." inode=1'
        assert parse_path_line(line) is None

    def test_correlate_builds_event(self):
        from fs_monitor.audit_parser import parse_syscall_line, parse_path_line, correlate
        syscall = parse_syscall_line(self._syscall_line())
        path    = parse_path_line(self._path_line())
        result  = correlate(syscall, path)

        assert result is not None
        assert result["path"]   == "/home/aya/secret.pdf"
        assert result["action"] == "opened"
        assert result["exe"]    == "/usr/bin/vim"

    def test_ignored_executable_filtered(self):
        from fs_monitor.audit_parser import parse_syscall_line
        result = parse_syscall_line(
            self._syscall_line(exe="/usr/libexec/tracker-extract-3")
        )
        assert result is None


class TestScreenParser:

    def _syscall_line(self, exe="/usr/bin/gnome-screenshot",
                      msg_id="1776075351.428:99001"):
        return (
            f'type=SYSCALL msg=audit({msg_id}): arch=c000003e syscall=59 '
            f'success=yes exit=0 ppid=1000 pid=1234 uid=1000 '
            f'comm="gnome-screenshot" exe="{exe}" '
            f'key="screen_monitor"ARCH=x86_64 SYSCALL=execve '
            f'AUID="aya" UID="aya"'
        )

    def _execve_line(self, args, msg_id="1776075351.428:99001"):
        argc     = len(args)
        args_str = " ".join(f'a{i}="{a}"' for i, a in enumerate(args))
        return f'type=EXECVE msg=audit({msg_id}): argc={argc} {args_str}'

    def _path_line(self, inode=5678901, msg_id="1776075351.428:99001"):
        return (
            f'type=PATH msg=audit({msg_id}): item=0 '
            f'name="/usr/bin/gnome-screenshot" inode={inode}'
        )

    def test_parse_syscall_correct_key(self):
        from screen_monitor.screen_parser import parse_syscall_line
        result = parse_syscall_line(self._syscall_line())
        assert result is not None
        assert result["exe"] == "/usr/bin/gnome-screenshot"
        assert result["pid"] == "1234"

    def test_parse_syscall_wrong_key_ignored(self):
        from screen_monitor.screen_parser import parse_syscall_line
        line = self._syscall_line().replace(
            'key="screen_monitor"', 'key="net_monitor"'
        )
        assert parse_syscall_line(line) is None

    def test_extract_output_path_from_flag(self):
        from screen_monitor.screen_parser import _extract_output_path
        assert _extract_output_path(["-f", "/tmp/s.png"]) == "/tmp/s.png"
        assert _extract_output_path(["-o", "/tmp/s.png"]) == "/tmp/s.png"
        assert _extract_output_path([])                   is None

    def test_correlate_exe_match(self):
        from screen_monitor.screen_parser import (
            parse_syscall_line, parse_execve_line,
            parse_path_line, correlate
        )
        syscall = parse_syscall_line(self._syscall_line())
        execve  = parse_execve_line(
            self._execve_line(["gnome-screenshot", "-f", "/tmp/s.png"])
        )
        path    = parse_path_line(self._path_line())

        tool_paths = {"gnome-screenshot": "/usr/bin/gnome-screenshot"}
        result = correlate(syscall, execve, path, {}, tool_paths)

        assert result is not None
        assert result["action"]           == "screenshot"
        assert result["detection_method"] == "exe_match"
        assert result["output_path"]      == "/tmp/s.png"

    def test_correlate_inode_match(self):
        from screen_monitor.screen_parser import (
            parse_syscall_line, parse_execve_line,
            parse_path_line, correlate
        )
        syscall = parse_syscall_line(
            self._syscall_line(exe="/tmp/backup_tool")
        )
        execve = parse_execve_line(self._execve_line(["backup_tool"]))
        path   = parse_path_line(self._path_line(inode=5678901))

        inode_map = {5678901: "/usr/bin/gnome-screenshot"}
        result    = correlate(syscall, execve, path, inode_map, {})

        assert result is not None
        assert result["detection_method"] == "inode_match"
        assert result["exe"]              == "/tmp/backup_tool"

    def test_unknown_tool_returns_none(self):
        from screen_monitor.screen_parser import (
            parse_syscall_line, parse_execve_line,
            parse_path_line, correlate
        )
        syscall = parse_syscall_line(self._syscall_line(exe="/usr/bin/nano"))
        execve  = parse_execve_line(self._execve_line(["nano"]))
        path    = parse_path_line(self._path_line(inode=9999999))

        assert correlate(syscall, execve, path, {}, {}) is None


class TestPrecursorParser:

    def _syscall(self, syscall="execve", exe="/usr/bin/sudo",
                 uid="1000", euid="0", auid="1000",
                 a2="0", key="precursor_priv",
                 msg_id="1777558048.391:99001"):
        return (
            f'type=SYSCALL msg=audit({msg_id}): arch=c000003e '
            f'syscall=59 success=yes exit=0 '
            f'a0=0 a1=0 a2={a2} a3=0 '
            f'ppid=1000 pid=2000 uid={uid} gid={uid} '
            f'euid={euid} auid={auid} tty=pts2 ses=3 '
            f'comm="sudo" exe="{exe}" '
            f'key="{key}"ARCH=x86_64 SYSCALL={syscall} '
            f'AUID="aya" UID="aya"'
        )

    def _execve(self, args, msg_id="1777558048.391:99001"):
        argc     = len(args)
        args_str = " ".join(f'a{i}="{a}"' for i, a in enumerate(args))
        return f'type=EXECVE msg=audit({msg_id}): argc={argc} {args_str}'

    def _path(self, name="/tmp/rootbash", msg_id="1777558048.391:99001"):
        return (
            f'type=PATH msg=audit({msg_id}): item=0 '
            f'name="{name}" inode=123456'
        )

    def test_sudo_execution_detected(self):
        from precursor_detector.precursor_parser import (
            parse_syscall_line, parse_execve_line, correlate
        )
        syscall = parse_syscall_line(self._syscall())
        execve  = parse_execve_line(self._execve(["sudo", "ls"]))
        result  = correlate(syscall, execve, None)

        assert result is not None
        assert result["category"]            == "sudo_execution"
        assert result["details"]["sudo_arg"] == "ls"

    def test_suid_set_detected(self):
        from precursor_detector.precursor_parser import (
            parse_syscall_line, parse_path_line, correlate
        )
        line = (
            'type=SYSCALL msg=audit(1777558048.391:9999): arch=c000003e '
            'syscall=268 success=yes exit=0 '
            'a0=ffffff9c a1=abc a2=800 a3=0 '
            'ppid=1000 pid=2001 uid=1000 gid=1000 '
            'euid=1000 auid=1000 tty=pts2 ses=3 '
            'comm="chmod" exe="/usr/bin/chmod" '
            'key="precursor_priv"ARCH=x86_64 SYSCALL=fchmodat '
            'AUID="aya" UID="aya"'
        )
        syscall = parse_syscall_line(line)
        path    = parse_path_line(self._path(msg_id="1777558048.391:9999"))
        result  = correlate(syscall, None, path)

        assert result is not None
        assert result["category"]        == "suid_set"
        assert result["details"]["suid"] is True

    def test_normal_chmod_ignored(self):
        from precursor_detector.precursor_parser import (
            parse_syscall_line, parse_path_line, correlate
        )
        line = (
            'type=SYSCALL msg=audit(1777558048.391:8888): arch=c000003e '
            'syscall=268 success=yes exit=0 '
            'a0=ffffff9c a1=abc a2=1ed a3=0 '
            'ppid=1000 pid=2002 uid=1000 gid=1000 '
            'euid=1000 auid=1000 tty=pts2 ses=3 '
            'comm="chmod" exe="/usr/bin/chmod" '
            'key="precursor_priv"ARCH=x86_64 SYSCALL=fchmodat '
            'AUID="aya" UID="aya"'
        )
        syscall = parse_syscall_line(line)
        path    = parse_path_line(self._path(msg_id="1777558048.391:8888"))
        assert correlate(syscall, None, path) is None

    def test_shadow_access_detected(self):
        from precursor_detector.precursor_parser import (
            parse_syscall_line, parse_path_line, correlate
        )
        syscall = parse_syscall_line(
            self._syscall(syscall="openat", exe="/usr/bin/cat",
                          key="precursor_file")
        )
        path   = parse_path_line(self._path(name="/etc/shadow"))
        result = correlate(syscall, None, path)

        assert result is not None
        assert result["category"]        == "shadow_access"
        assert result["details"]["path"] == "/etc/shadow"

    def test_encryption_tool_detected(self):
        from precursor_detector.precursor_parser import (
            parse_syscall_line, parse_execve_line, correlate
        )
        syscall = parse_syscall_line(
            self._syscall(exe="/usr/bin/gpg", key="precursor_crypt")
        )
        execve  = parse_execve_line(
            self._execve(["gpg", "-c", "secret.csv"])
        )
        result  = correlate(syscall, execve, None)

        assert result is not None
        assert result["category"]          == "encryption_tool"
        assert result["details"]["intent"] == "encrypt"

    def test_payload_has_no_severity(self):
        from precursor_detector.precursor_parser import (
            parse_syscall_line, parse_execve_line, correlate
        )
        syscall = parse_syscall_line(self._syscall())
        execve  = parse_execve_line(self._execve(["sudo", "vim"]))
        result  = correlate(syscall, execve, None)

        assert "severity"   not in result
        assert "risk_score" not in result

    def test_wrong_key_ignored(self):
        from precursor_detector.precursor_parser import parse_syscall_line
        line   = self._syscall(key="net_monitor")
        result = parse_syscall_line(line)
        assert result is None


class TestTransferSession:

    def _make_session(self, mount_point="/media/usb", on_closed=None):
        from usb_monitor.transfer_session import TransferSession
        return TransferSession(
            device_node="/dev/sdb1",
            device_info={"id_vendor": "Test",
                         "id_model":  "USB",
                         "id_serial": "SN001"},
            mount_point=mount_point,
            on_closed=on_closed,
        )

    def test_record_file_adds_entry(self, tmp_path):
        session = self._make_session()
        f = tmp_path / "doc.pdf"
        f.write_bytes(b"x" * 200)

        with patch("usb_monitor.transfer_session._get_process_info",
                   return_value={"pid": "42", "exe": "/usr/bin/cp",
                                 "uid": "1000", "auid": "1000",
                                 "username": "aya"}):
            session.record_file("created", str(f))

        assert len(session.files)        == 1
        assert session.total_bytes       == 200
        assert session.files[0]["extension"] == ".pdf"
        assert session.files[0]["pid"]       == "42"
        session._timer.cancel()

    def test_finalize_idempotent(self, tmp_path):
        written = []

        with patch("usb_monitor.transfer_session.db") as mock_db:
            mock_db.write_event = MagicMock(side_effect=lambda t, p: written.append(p))
            session = self._make_session()
            session.finalize()
            session.finalize()  

        assert len(written) == 1

    def test_on_closed_callback_called(self):
        callback = MagicMock()
        with patch("usb_monitor.transfer_session.db"):
            session = self._make_session(on_closed=callback)
            session.finalize()
        callback.assert_called_once_with("/dev/sdb1")

    def test_inactivity_timer_fires(self, tmp_path):
        import usb_monitor.config as cfg
        closed = threading.Event()

        with patch.object(cfg, "SESSION_INACTIVITY_TIMEOUT", 0.3):
            with patch("usb_monitor.transfer_session.db"):
                session = self._make_session(
                    on_closed=lambda _: closed.set()
                )
                fired = closed.wait(timeout=2)

        assert fired, "Inactivity timer did not fire"

    def test_payload_has_no_severity(self, tmp_path):
        payloads = []
        with patch("usb_monitor.transfer_session.db") as mock_db:
            mock_db.write_event = MagicMock(
                side_effect=lambda t, p: payloads.append(p)
            )
            session = self._make_session()
            session.finalize()

        assert len(payloads) == 1
        assert "severity"        not in payloads[0]
        assert "risk_multiplier" not in payloads[0]
        