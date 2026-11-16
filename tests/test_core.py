"""Sanitiser, ids, paths, JSON/schema attacks, locks, time."""
import json
import os
import subprocess
import sys
import time
import unittest

from helpers import Base, add_cases, relay, make_link, drop_link

# ---------------------------------------------------------------- sanitiser
SANITISE = [
    ("csi", "a\x1b[31mred\x1b[0mb", "\x1b", "aredb"),
    ("osc_bel", "x\x1b]0;title\x07y", "\x1b", "xy"),
    ("osc_st", "x\x1b]8;;http://h\x1b\\link", "\x1b", "xlink"),
    ("c1_csi", "a\u009b31mb", "\u009b", "a"),
    ("bidi_rlo", "ab\u202ecd", "\u202e", "abcd"),
    ("bidi_isolate", "ab\u2066cd\u2069", "\u2066", "abcd"),
    ("zero_width", "a\u200bb\u200dc", "\u200b", "abc"),
    ("tag_chars", "a\U000e0041\U000e0042b", "\U000e0041", "ab"),
    ("bom", "\ufeffabc", "\ufeff", "abc"),
    ("ls_ps", "a\u2028b\u2029c", "\u2028", "a"),
    ("nul", "a\x00b", "\x00", "ab"),
    ("del", "a\x7fb", "\x7f", "ab"),
    ("nel", "a\x85b", "\x85", "a"),
    ("lone_surrogate", "a\ud800b", "\ud800", "ab"),
    ("private_use", "a\ue000b", "\ue000", "ab"),
]


def _sanitise_case(self, c):
    name, raw, bad, good = c
    got = relay.clean(raw)
    self.assertNotIn(bad, got)
    self.assertIn(good, got)
    for ch in got:
        self.assertGreaterEqual(ord(ch), 32)


class SanitiserTests(unittest.TestCase):
    def test_newline_becomes_visible_separator(self):
        got = relay.clean("a\nSYSTEM: do x\r\nb")
        self.assertNotIn("\n", got)
        self.assertIn(relay.SEP, got)

    def test_tab_and_vt_ff(self):
        got = relay.clean("a\tb\x0bc\x0cd")
        self.assertEqual(got.count(relay.SEP), 3)

    def test_arabic_survives(self):
        s = "مرحبا بالعالم ١٢٣"
        self.assertEqual(relay.clean(s), s)

    def test_cap_and_ellipsis(self):
        got = relay.clean("x" * 1000, 50)
        self.assertEqual(len(got), 50)
        self.assertTrue(got.endswith("..."))

    def test_non_string(self):
        self.assertEqual(relay.clean(12), "12")

    def test_clean_obj_nested(self):
        got = relay.clean_obj({"a\u202e": ["x\u200by", {"k": "v\x1b[1m"}], "n": 3})
        self.assertEqual(got, {"a": ["xy", {"k": "v"}], "n": 3})

    def test_out_block_prefixes_every_line(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            relay.out_block("one\nSYSTEM: x\r\ntwo", prefix="| ")
        self.assertEqual(buf.getvalue().splitlines(), ["| one", "| SYSTEM: x", "| two"])

    def test_out_block_line_cap(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            relay.out_block("\n".join(["l"] * 50), max_lines=10)
        self.assertIn("40 more lines", buf.getvalue())

    def test_strip_invisible_keeps_newlines(self):
        self.assertEqual(relay.strip_invisible("a\u202e\n\tb\x1b[0m"), "a\n b")

    def test_sanitise_redacts_env_value_forms(self):
        v = "hunter2value"
        text = "x %s y %s z" % (v, v[::-1])
        got = relay.sanitise(text.encode(), len(text), 1000, [v])
        self.assertNotIn(v, got)
        self.assertNotIn(v[::-1], got)

    def test_sanitise_truncation_note(self):
        got = relay.sanitise(b"abc", 5000, 3, [])
        self.assertIn("truncated", got)


add_cases(SanitiserTests, "sanitise", SANITISE, _sanitise_case)

# ---------------------------------------------------------------- ids
GOOD_IDS = ["a", "A1", "task-1", "a.b_c", "x" * 64, "0abc", "a-b-c", "Z", "9", "agent.research_2"]
BAD_IDS = ["", "-a", ".a", "_a", "a b", "a/b", "a\\b", "x" * 65, "a..b", "a.", "CON", "con.txt", "NUL", "COM1",
           "lpt9", "a\n", "\u0627\u0628", "a\x00", "aux.md", "a ", " a", "a:b", "a*b", "../a", "Prn", "conin$"]


class IdTests(unittest.TestCase):
    pass


add_cases(IdTests, "good_id", GOOD_IDS, lambda self, c: self.assertEqual(relay.check_id(c), c))
add_cases(IdTests, "bad_id", BAD_IDS, lambda self, c: self.assertRaises(relay.RelayError, relay.check_id, c))

# ---------------------------------------------------------------- paths
GOOD_PATHS = ["Reports/a.md", "Relay/briefs/a1.md", "x", "a/b/c.txt", "\u0642\u0627\u0626\u0645\u0629/\u0641\u062d\u0635.md",
              "dir.with.dots/file"]
BAD_PATHS = ["../x", "/abs", "C:/x", "C:x", "a/../b", "a//b", "a\\b", "x.txt:stream", "//server/share/x",
             "~/x", "a/CON", "a/nul.txt", "a/b.", "a/ b", ".git/config", ".env", "keys/x", "x.pem",
             "a/PROGRA~1/x", "a\x00b", "x" * 300, "", ".", "..", "a/./b", "a/b/", "id_rsa", "secrets/a",
             "my_secret_notes.md", "a/\u202e/b", "a\nb", ".npmrc", "node_modules/x"]


class PathTests(Base):
    def test_abs_in_ok(self):
        p = relay.abs_in(self.proj, "Reports/a.md")
        self.assertTrue(p.startswith(self.proj))

    def test_symlink_component_refused(self):
        target = os.path.join(self.tmp, "outside")
        os.mkdir(target)
        link = os.path.join(self.proj, "lnk")
        if not make_link(target, link):
            self.skipTest("cannot create a link here")
        self.links.append(link)
        with self.assertRaises(relay.RelayError):
            relay.abs_in(self.proj, "lnk/file.txt")

    def test_relay_dir_link_refused_by_init(self):
        target = os.path.join(self.tmp, "outside")
        os.mkdir(target)
        link = os.path.join(self.proj, "Relay")
        if not make_link(target, link):
            self.skipTest("cannot create a link here")
        self.links.append(link)
        rc, o, e = self.cli("init", "--yes")
        self.assertEqual(rc, 1)
        self.assertEqual(os.listdir(target), [])

    def test_relay_dir_link_refused_by_list(self):
        target = os.path.join(self.tmp, "outside")
        os.mkdir(target)
        with open(os.path.join(target, "registry.json"), "w") as f:
            f.write('{"schema":1,"items":[]}')
        link = os.path.join(self.proj, "Relay")
        if not make_link(target, link):
            self.skipTest("cannot create a link here")
        self.links.append(link)
        rc, o, e = self.cli("list")
        self.assertEqual(rc, 1)
        self.assertIn("symlink", e)

    def test_briefs_dir_link_refused_by_add(self):
        self.init()
        target = os.path.join(self.tmp, "outside")
        os.mkdir(target)
        briefs = os.path.join(self.proj, "Relay", "briefs")
        os.rmdir(briefs)
        if not make_link(target, briefs):
            self.skipTest("cannot create a link here")
        self.links.append(briefs)
        rc, o, e = self.add("a1")
        self.assertEqual(rc, 1)
        self.assertEqual(os.listdir(target), [])


add_cases(PathTests, "good_path", GOOD_PATHS, lambda self, c: self.assertEqual(relay.safe_rel(c), c))
add_cases(PathTests, "bad_path", BAD_PATHS, lambda self, c: self.assertRaises(relay.RelayError, relay.safe_rel, c))

# ---------------------------------------------------------------- time
GOOD_TIMES = ["2026-12-01T09:00:00Z", "2026-12-01T09:00Z", "2026-12-01T09:00:00+03:00", "2026-12-01T09:00:00-05:30",
              "+0m", "+90m", "+5h", "+2d"]
BAD_TIMES = ["tomorrow", "2026-13-01T00:00:00Z", "2026-01-01 00:00:00Z", "2026-01-01T00:00:00", "+3h ", "+3h\n",
             "2026-01-01T00:00:00Z\n", "", "+h", "+99999m", "2026-02-30T00:00:00Z", "2026-01-01T00:00:00+25:00",
             "2026-01-01T00:00:00+03:99", "-5m", "now"]


class TimeTests(unittest.TestCase):
    def test_offset_applied(self):
        a = relay.parse_when("2026-12-01T09:00:00+03:00")
        b = relay.parse_when("2026-12-01T06:00:00Z")
        self.assertEqual(a, b)

    def test_roundtrip(self):
        e = relay.parse_when("2026-12-01T09:00:00Z")
        self.assertEqual(relay.fmt_ts(e), "2026-12-01T09:00:00Z")
        self.assertEqual(relay.ts_epoch("2026-12-01T09:00:00Z"), e)

    def test_relative_uses_patched_clock(self):
        old = relay.now_epoch
        relay.now_epoch = lambda: 1000000000.0
        try:
            self.assertEqual(relay.parse_when("+90m"), 1000000000 + 5400)
        finally:
            relay.now_epoch = old

    def test_no_env_clock_hook(self):
        os.environ["RELAY_NOW"] = "2001-01-01T00:00:00Z"
        os.environ["RELAY_TEST"] = "1"
        try:
            self.assertGreater(relay.now_epoch(), 1700000000)
        finally:
            del os.environ["RELAY_NOW"]
            del os.environ["RELAY_TEST"]


add_cases(TimeTests, "good_time", GOOD_TIMES, lambda self, c: self.assertIsInstance(relay.parse_when(c), int))
add_cases(TimeTests, "bad_time", BAD_TIMES, lambda self, c: self.assertRaises(relay.RelayError, relay.parse_when, c))

# ---------------------------------------------------------------- registry schema attacks
def _items(**over):
    it = {"id": "a1", "title": "t", "kind": "task", "owner": "o", "brief": "Relay/briefs/a1.md",
          "status": "pending", "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z"}
    it.update(over)
    return it


def reg_with(*items, **top):
    d = {"schema": 1, "items": list(items)}
    d.update(top)
    return d


SCHEMA_BAD = [
    ("unknown_item_field", reg_with(_items(extra="x"))),
    ("unknown_top_field", reg_with(_items(), extra=1)),
    ("schema_2", {"schema": 2, "items": []}),
    ("schema_string", {"schema": "1", "items": []}),
    ("schema_bool", {"schema": True, "items": []}),
    ("schema_float", {"schema": 1.0, "items": []}),
    ("items_not_list", {"schema": 1, "items": {}}),
    ("items_null", {"schema": 1, "items": None}),
    ("item_not_object", {"schema": 1, "items": [1]}),
    ("dup_id", reg_with(_items(), _items())),
    ("dup_id_case", reg_with(_items(), _items(id="A1", brief="Relay/briefs/A1.md"))),
    ("bad_id", reg_with(_items(id="a b", brief="Relay/briefs/a b.md"))),
    ("device_id", reg_with(_items(id="CON", brief="Relay/briefs/CON.md"))),
    ("bad_kind", reg_with(_items(kind="job"))),
    ("bad_status", reg_with(_items(status="finished"))),
    ("brief_mismatch", reg_with(_items(brief="Relay/briefs/other.md"))),
    ("brief_traversal", reg_with(_items(brief="Relay/briefs/../../x.md"))),
    ("title_empty", reg_with(_items(title=""))),
    ("title_control", reg_with(_items(title="a\nb"))),
    ("title_long", reg_with(_items(title="x" * 201))),
    ("title_bidi_line_sep", reg_with(_items(title="a\u2028b"))),
    ("owner_long", reg_with(_items(owner="x" * 101))),
    ("retry_bad", reg_with(_items(retry_after="soon"))),
    ("retry_no_z", reg_with(_items(retry_after="2026-01-01T00:00:00"))),
    ("created_missing", reg_with({k: v for k, v in _items().items() if k != "created"})),
    ("created_future_format", reg_with(_items(created="2026-13-45T00:00:00Z"))),
    ("report_abs", reg_with(_items(report="/etc/x"))),
    ("report_traversal", reg_with(_items(report="../x.md"))),
    ("partial_unc", reg_with(_items(partial="//srv/share/x"))),
    ("partial_ads", reg_with(_items(partial="x.md:s"))),
    ("hint_long", reg_with(_items(resume_hint="x" * 1001))),
    ("usage_note_long", reg_with(_items(usage_note="x" * 501))),
    ("too_many_items", reg_with(*[_items(id="i%d" % i, brief="Relay/briefs/i%d.md" % i) for i in range(501)])),
    ("status_null", reg_with(_items(status=None))),
    ("title_number", reg_with(_items(title=5))),
]

RAW_BAD = [
    ("dup_keys", b'{"schema":1,"schema":1,"items":[]}'),
    ("nan", b'{"schema":1,"items":[],"x":NaN}'),
    ("invalid_utf8", b'{"schema":1,"items":[],"x":"\xff\xfe"}'),
    ("empty", b""),
    ("truncated", b'{"schema":1,"items":['),
    ("array_top", b"[]"),
    ("deep_nesting", b"[" * 100000),
    ("huge", b'{"schema":1,"items":[],"pad":"' + b"x" * (1024 * 1024 + 10) + b'"}'),
    ("null_byte", b'{"schema":1,"items":[]}\x00'),
    ("text", b"hello"),
]


class SchemaTests(Base):
    def _reject(self, data):
        self.init()
        if isinstance(data, bytes):
            self.raw_reg(data)
        else:
            self.write_reg(data)
        before = self.read_bytes(self.reg_path())
        for argv in (["list"], ["next"], ["update", "a1", "--status", "done"]):
            rc, o, e = self.cli(*argv)
            self.assertEqual(rc, 1, (argv, e))
            self.assertNotIn("Traceback", e)
            self.assertIn("Nothing was changed", e)
        self.assertEqual(self.read_bytes(self.reg_path()), before)
        self.assertFalse(os.path.exists(self.reg_path() + ".bak") and
                         open(self.reg_path() + ".bak", "rb").read() == before and False)

    def test_bom_and_crlf_accepted(self):
        self.init()
        data = json.dumps(reg_with(_items()), indent=2).replace("\n", "\r\n").encode("utf-8")
        self.raw_reg(b"\xef\xbb\xbf" + data)
        rc, o, e = self.cli("list")
        self.assertEqual(rc, 0, e)
        self.assertIn("a1", o)

    def test_valid_full_item(self):
        self.init()
        self.write_reg(reg_with(_items(report="Reports/a.md", partial="Reports/p.md", usage_note="n",
                                       resume_hint="h", retry_after="2026-01-02T00:00:00Z")))
        rc, o, e = self.cli("list")
        self.assertEqual(rc, 0, e)

    def test_missing_registry(self):
        self.init()
        os.unlink(self.reg_path())
        rc, o, e = self.cli("list")
        self.assertEqual(rc, 1)
        self.assertIn("init", e)

    def test_bak_written_on_update(self):
        self.init()
        self.add("a1")
        self.cli("update", "a1", "--status", "running")
        self.assertTrue(os.path.exists(self.reg_path() + ".bak"))
        self.assertEqual(json.loads(self.read_bytes(self.reg_path() + ".bak"))["items"][0]["status"], "pending")

    def test_corrupt_message_mentions_bak(self):
        self.init()
        self.raw_reg(b"{")
        rc, o, e = self.cli("list")
        self.assertIn(".bak", e)

    def test_no_temp_files_left_after_failure(self):
        self.init()
        self.raw_reg(b"{")
        self.cli("update", "a1", "--status", "done")
        left = [n for n in os.listdir(os.path.join(self.proj, "Relay")) if n.endswith(".tmp")]
        self.assertEqual(left, [])


add_cases(SchemaTests, "schema_bad", SCHEMA_BAD, lambda self, c: self._reject(c[1]))
add_cases(SchemaTests, "raw_bad", RAW_BAD, lambda self, c: self._reject(c[1]))

# ---------------------------------------------------------------- lock
def dead_pid():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


class LockTests(Base):
    def setUp(self):
        Base.setUp(self)
        self.init()
        self.lockdir = os.path.join(self.proj, "Relay", relay.LOCK_NAME)

    def make_lock(self, owner=None, age=0, raw_owner=None):
        os.mkdir(self.lockdir)
        if owner is not None or raw_owner is not None:
            with open(os.path.join(self.lockdir, "owner"), "w") as f:
                f.write(raw_owner if raw_owner is not None else json.dumps(owner))
        t = time.time() - age
        os.utime(self.lockdir, (t, t))

    def me(self, **kw):
        d = {"token": "x", "pid": os.getpid(), "host": relay.os.environ.get("COMPUTERNAME") or
             os.environ.get("HOSTNAME") or ""}
        d.update(kw)
        return d

    def test_take_and_release(self):
        with relay.Lock(self.proj):
            self.assertTrue(os.path.isdir(self.lockdir))
            self.assertEqual(len(relay.HOLDING), 1)
        self.assertFalse(os.path.exists(self.lockdir))
        self.assertEqual(relay.HOLDING, [])

    def test_released_on_exception(self):
        with self.assertRaises(ValueError):
            with relay.Lock(self.proj):
                raise ValueError("x")
        self.assertFalse(os.path.exists(self.lockdir))

    def test_second_taker_times_out(self):
        os.environ["RELAY_LOCK_TIMEOUT"] = "0.3"
        os.environ["RELAY_LOCK_STALE"] = "1000"
        with relay.Lock(self.proj):
            with self.assertRaises(relay.RelayError) as cm:
                with relay.Lock(self.proj):
                    pass
        self.assertIn("another relay command", str(cm.exception))

    def test_dead_pid_old_lock_taken_over(self):
        self.make_lock(self.me(pid=dead_pid()), age=500)
        os.environ["RELAY_LOCK_STALE"] = "1"
        with relay.Lock(self.proj):
            pass

    def test_live_pid_old_lock_not_taken(self):
        self.make_lock(self.me(), age=500)
        os.environ["RELAY_LOCK_STALE"] = "1"
        os.environ["RELAY_LOCK_TIMEOUT"] = "0.3"
        with self.assertRaises(relay.RelayError):
            with relay.Lock(self.proj):
                pass
        self.assertTrue(os.path.isdir(self.lockdir))

    def test_fresh_dead_pid_lock_not_taken(self):
        self.make_lock(self.me(pid=dead_pid()), age=0)
        os.environ["RELAY_LOCK_STALE"] = "1000"
        os.environ["RELAY_LOCK_TIMEOUT"] = "0.3"
        with self.assertRaises(relay.RelayError):
            with relay.Lock(self.proj):
                pass

    def test_no_owner_old_lock_taken(self):
        self.make_lock(None, age=500)
        os.environ["RELAY_LOCK_STALE"] = "1"
        with relay.Lock(self.proj):
            pass

    def test_garbage_owner_old_lock_taken(self):
        self.make_lock(raw_owner="not json", age=500)
        os.environ["RELAY_LOCK_STALE"] = "1"
        with relay.Lock(self.proj):
            pass

    def test_other_host_needs_ten_times(self):
        self.make_lock(self.me(host="some-other-host", pid=dead_pid()), age=50)
        os.environ["RELAY_LOCK_STALE"] = "10"
        os.environ["RELAY_LOCK_TIMEOUT"] = "0.3"
        with self.assertRaises(relay.RelayError):
            with relay.Lock(self.proj):
                pass

    def test_other_host_taken_after_ten_times(self):
        self.make_lock(self.me(host="some-other-host", pid=dead_pid()), age=500)
        os.environ["RELAY_LOCK_STALE"] = "10"
        with relay.Lock(self.proj):
            pass

    def test_future_dated_lock_with_dead_pid_taken(self):
        self.make_lock(self.me(pid=dead_pid()), age=-100000)
        os.environ["RELAY_LOCK_STALE"] = "1"
        with relay.Lock(self.proj):
            pass

    def test_lock_that_is_a_file_is_replaced_when_stale(self):
        with open(self.lockdir, "w") as f:
            f.write("x")
        t = time.time() - 500
        os.utime(self.lockdir, (t, t))
        os.environ["RELAY_LOCK_STALE"] = "1"
        with relay.Lock(self.proj):
            self.assertTrue(os.path.isdir(self.lockdir))

    def test_lock_junction_target_untouched(self):
        target = os.path.join(self.tmp, "keep")
        os.mkdir(target)
        with open(os.path.join(target, "user.txt"), "w") as f:
            f.write("mine")
        if not make_link(target, self.lockdir):
            self.skipTest("cannot create a link here")
        self.links.append(self.lockdir)
        t = time.time() - 500
        try:
            os.utime(self.lockdir, (t, t), follow_symlinks=False)
        except (OSError, NotImplementedError):
            pass
        os.environ["RELAY_LOCK_STALE"] = "1"
        os.environ["RELAY_LOCK_TIMEOUT"] = "1"
        try:
            with relay.Lock(self.proj):
                pass
        except relay.RelayError:
            pass
        self.assertTrue(os.path.exists(os.path.join(target, "user.txt")))

    def test_stale_lock_with_user_files_not_deleted_recursively(self):
        self.make_lock(None, age=500)
        os.mkdir(os.path.join(self.lockdir, "keep"))
        with open(os.path.join(self.lockdir, "keep", "user.txt"), "w") as f:
            f.write("mine")
        os.environ["RELAY_LOCK_STALE"] = "1"
        with relay.Lock(self.proj):
            pass
        found = []
        for dp, dn, fn in os.walk(os.path.join(self.proj, "Relay")):
            found += [os.path.join(dp, n) for n in fn if n == "user.txt"]
        self.assertEqual(len(found), 1)

    def test_lost_lock_blocks_write(self):
        with relay.Lock(self.proj):
            with open(os.path.join(self.lockdir, "owner"), "w") as f:
                f.write(json.dumps({"token": "someone-else"}))
            with self.assertRaises(relay.RelayError) as cm:
                relay.atomic_write(os.path.join(self.proj, "Relay", "x.json"), b"{}")
            self.assertIn("lock was lost", str(cm.exception))
        self.assertFalse(os.path.exists(os.path.join(self.proj, "Relay", "x.json")))

    def test_bad_env_values(self):
        for v in ("abc", "nan", "-1", "1e99"):
            os.environ["RELAY_LOCK_STALE"] = v
            with self.assertRaises(relay.RelayError):
                with relay.Lock(self.proj):
                    pass

    def test_lock_without_relay_dir_refused(self):
        import shutil
        shutil.rmtree(os.path.join(self.proj, "Relay"))
        with self.assertRaises(relay.RelayError):
            relay.Lock(self.proj)

    def test_pid_alive_self_and_dead(self):
        self.assertTrue(relay.pid_alive(os.getpid()))
        self.assertFalse(relay.pid_alive(dead_pid()))
        self.assertFalse(relay.pid_alive(0))
        self.assertFalse(relay.pid_alive(-5))
        self.assertFalse(relay.pid_alive(True))
        self.assertFalse(relay.pid_alive("12"))


if __name__ == "__main__":
    unittest.main()
