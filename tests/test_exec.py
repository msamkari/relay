"""No-shell execution, program resolution, tree kill, env allow-list, output handling."""
import json
import os
import shutil
import stat
import sys
import time
import unittest

from helpers import Base, add_cases, relay

BAD_PROGRAMS = ["cmd", "cmd.exe", "CMD.EXE", "cmd.exe.", "cmd ", " cmd", "powershell", "powershell.exe", "pwsh",
                "bash", "bash.exe", "sh", "sh.exe", "zsh", "env", "env.exe", "forfiles", "wscript", "cscript",
                "mshta", "rundll32", "regsvr32", "wmic", "timeout", "start", "wsl", "sudo", "xargs", "nohup",
                "x.bat", "x.cmd", "x.ps1", "x.vbs", "x.js", "x.hta", "x.jar", "foo.py", "foo.sh",
                "git.bat", "git.cmd", "./git", ".\\git", "C:\\Windows\\System32\\cmd.exe", "/bin/sh", "..\\x",
                "dir/git", "git:stream", "git~1", "", "git.", "git*", "x.bat.", "CMD.exe.exe"]

GOOD_PROGRAMS = ["git", "gh", "git.exe", "pytest", "node", "python3", "make"]


def _bad_program(self, name):
    self.assertIsNotNone(relay.program_problem(name), repr(name))


def _good_program(self, name):
    self.assertIsNone(relay.program_problem(name), repr(name))


BAD_TOKENS = [
    ("empty_argv", []),
    ("not_a_list", "git status"),
    ("non_string_token", ["git", 5]),
    ("empty_token", ["git", ""]),
    ("control_char", ["git", "a\nb"]),
    ("bidi_char", ["git", "a\u202eb"]),
    ("ansi", ["git", "\x1b[31m"]),
    ("long_token", ["git", "x" * 501]),
    ("too_many", ["git"] + ["x"] * 40),
    ("brace_suffix", ["git", "{branch}:main"]),
    ("brace_prefix", ["git", "+{branch}"]),
    ("brace_inside", ["git", "a{branch}b"]),
    ("unknown_placeholder", ["git", "{evil}"]),
    ("open_brace", ["git", "{"]),
    ("python_not_first", ["git", "{python}"]),
    ("relay_not_first", ["git", "{relay}"]),
    ("branch_as_program", ["{branch}", "x"]),
    ("sha_as_program", ["{sha}"]),
    ("shell_program", ["bash", "-c", "x"]),
    ("bat_program", ["run.bat"]),
]

GOOD_TOKENS = [["git", "status"], ["{python}", "-c", "pass"], ["{relay}", "verify-authors"], ["git", "{branch}"],
               ["gh", "x", "{sha}", "{tag}", "{repo}", "{target}"], ["pytest", "-q", "tests/test_x.py"]]


class ProgramTests(Base):
    def test_validate_good_tokens(self):
        for argv in GOOD_TOKENS:
            relay.validate_tokens(argv, "w")

    def planted(self, name, where):
        os.makedirs(where, exist_ok=True)
        fname = name + (".exe" if os.name == "nt" else "")
        p = os.path.join(where, fname)
        shutil.copyfile(sys.executable, p)
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXUSR)
        return p

    def with_path(self, *dirs):
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = os.pathsep.join(dirs)
        self.addCleanup(lambda: os.environ.__setitem__("PATH", old))

    def test_found_on_path(self):
        b = os.path.join(self.tmp, "bin")
        p = self.planted("faketoolx", b)
        self.with_path(b)
        self.assertEqual(os.path.normcase(relay.find_program("faketoolx", self.proj)), os.path.normcase(p))

    def test_project_folder_never_searched(self):
        self.planted("faketoolx", self.proj)
        self.with_path(self.proj)
        with self.assertRaises(relay.RelayError):
            relay.find_program("faketoolx", self.proj)

    def test_project_subfolder_never_searched(self):
        d = os.path.join(self.proj, "tools")
        self.planted("faketoolx", d)
        self.with_path(d)
        with self.assertRaises(relay.RelayError):
            relay.find_program("faketoolx", self.proj)

    def test_cwd_never_searched(self):
        other = os.path.join(self.tmp, "elsewhere")
        self.planted("faketoolx", other)
        self.with_path(other)
        old = os.getcwd()
        os.chdir(other)
        try:
            with self.assertRaises(relay.RelayError):
                relay.find_program("faketoolx", self.proj)
        finally:
            os.chdir(old)

    def test_relative_path_entries_ignored(self):
        self.planted("faketoolx", os.path.join(self.tmp, "bin"))
        os.chdir(self.tmp)
        self.with_path("bin", ".", "")
        with self.assertRaises(relay.RelayError):
            relay.find_program("faketoolx", self.proj)

    def test_not_found(self):
        self.with_path(os.path.join(self.tmp, "empty"))
        with self.assertRaises(relay.RelayError):
            relay.find_program("faketoolx", self.proj)

    def test_planted_shadow_does_not_win(self):
        real = os.path.join(self.tmp, "bin")
        evil = os.path.join(self.proj, "evil")
        rp = self.planted("faketoolx", real)
        self.planted("faketoolx", evil)
        self.with_path(evil, real)
        self.assertEqual(os.path.normcase(relay.find_program("faketoolx", self.proj)), os.path.normcase(rp))

    def test_shell_name_refused_by_find(self):
        for n in ("cmd", "bash", "env"):
            with self.assertRaises(relay.RelayError):
                relay.find_program(n, self.proj)


add_cases(ProgramTests, "bad_program", BAD_PROGRAMS, _bad_program)
add_cases(ProgramTests, "good_program", GOOD_PROGRAMS, _good_program)
add_cases(ProgramTests, "bad_tokens", BAD_TOKENS,
          lambda self, c: self.assertRaises(relay.RelayError, relay.validate_tokens, c[1], "w"))


PY = sys.executable


class RunTests(Base):
    def run_py(self, code, timeout=30, cap=20000, env=()):
        return relay.run_argv([PY, "-c", code], self.proj, timeout=timeout, cap=cap, env_names=env)

    def test_success_output(self):
        rc, text, to = self.run_py("print('hello')")
        self.assertEqual((rc, text.strip(), to), (0, "hello", False))

    def test_exit_code(self):
        rc, text, to = self.run_py("import sys;sys.exit(7)")
        self.assertEqual(rc, 7)

    def test_stderr_merged(self):
        rc, text, to = self.run_py("import sys;sys.stderr.write('oops')")
        self.assertIn("oops", text)

    def test_cwd_is_project(self):
        rc, text, to = self.run_py("import os;print(os.getcwd())")
        self.assertEqual(os.path.normcase(os.path.realpath(text.strip())), os.path.normcase(self.proj))

    def test_stdin_is_empty(self):
        rc, text, to = self.run_py("import sys;print(repr(sys.stdin.read()))", timeout=10)
        self.assertEqual(text.strip(), "''")

    def test_timeout(self):
        t0 = time.time()
        rc, text, to = self.run_py("import time;time.sleep(30)", timeout=1)
        self.assertTrue(to)
        self.assertLess(time.time() - t0, 15)

    def test_output_cap(self):
        rc, text, to = self.run_py("import sys;sys.stdout.write('x'*3000000)", cap=1000)
        self.assertLess(len(text), 1200)
        self.assertIn("truncated", text)

    def test_output_sanitised(self):
        rc, text, to = self.run_py("print('a\\x1b[31mb\\u202ec\\u200bd')")
        self.assertEqual(text.strip(), "abcd")

    def test_secret_like_output_redacted(self):
        code = "print('k ' + 'ghp_' + 'A'*36)"
        rc, text, to = self.run_py(code)
        self.assertNotIn("ghp_", text)
        self.assertIn("redacted", text)

    def test_missing_program(self):
        rc, text, to = relay.run_argv(["definitely-not-a-program-xyz"], self.proj)
        self.assertIsNone(rc)
        self.assertIn("could not start", text)

    def test_shell_wrapper_refused_at_run(self):
        for prog in ("cmd", "bash", "powershell", "env", "sh"):
            rc, text, to = relay.run_argv([prog, "-c", "echo x"], self.proj)
            self.assertIsNone(rc, prog)

    def test_bat_refused_at_run(self):
        self.write_file("t.bat", "@echo hi\r\n")
        for prog in ("t.bat", "./t.bat", os.path.join(self.proj, "t.bat")):
            rc, text, to = relay.run_argv([prog], self.proj)
            self.assertIsNone(rc, prog)

    def test_no_shell_metacharacters_are_literal(self):
        code = "import sys;print(sys.argv[1])"
        payload = 'x" & echo INJ>inj.txt & rem "; touch inj2.txt | echo $(id) `id`'
        rc, text, to = relay.run_argv([PY, "-c", code, payload], self.proj)
        self.assertEqual(rc, 0)
        self.assertIn("echo INJ", text)
        self.assertFalse(os.path.exists(os.path.join(self.proj, "inj.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.proj, "inj2.txt")))

    def test_env_allow_list(self):
        os.environ["FAKE_VALUE_X"] = "sekret-value-123"
        os.environ["GIT_DIR"] = "/nonexistent"
        os.environ["OTHER_THING"] = "o"
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ("FAKE_VALUE_X", "GIT_DIR", "OTHER_THING")])
        rc, text, to = self.run_py("import os;print(sorted(os.environ))")
        self.assertNotIn("FAKE_VALUE_X", text)
        self.assertNotIn("GIT_DIR", text)
        self.assertNotIn("OTHER_THING", text)
        self.assertNotIn("RELAY_HOME", text)

    def test_named_env_needs_user_allow_list(self):
        os.environ["FAKE_VALUE_X"] = "sekret-value-123"
        self.addCleanup(lambda: os.environ.pop("FAKE_VALUE_X", None))
        rc, text, to = self.run_py("import os;print('FAKE_VALUE_X' in os.environ)", env=["FAKE_VALUE_X"])
        self.assertEqual(text.strip(), "False")
        os.makedirs(self.home)
        with open(os.path.join(self.home, "env_allow.json"), "w") as f:
            json.dump({"allow": ["FAKE_VALUE_X"]}, f)
        rc, text, to = self.run_py("import os;print('FAKE_VALUE_X' in os.environ)", env=["FAKE_VALUE_X"])
        self.assertEqual(text.strip(), "True")

    def test_allowed_env_value_redacted_in_output(self):
        os.environ["FAKE_VALUE_X"] = "sekret-value-123"
        self.addCleanup(lambda: os.environ.pop("FAKE_VALUE_X", None))
        os.makedirs(self.home)
        with open(os.path.join(self.home, "env_allow.json"), "w") as f:
            json.dump({"allow": ["FAKE_VALUE_X"]}, f)
        rc, text, to = self.run_py("import os;v=os.environ['FAKE_VALUE_X'];print(v, v[::-1])", env=["FAKE_VALUE_X"])
        self.assertNotIn("sekret-value-123", text)
        self.assertNotIn("sekret-value-123"[::-1], text)

    def marker_test(self, code, wait=4.0, timeout=30):
        marker = os.path.join(self.proj, "marker.txt")
        rc, text, to = relay.run_argv([PY, "-c", code], self.proj, timeout=timeout)
        time.sleep(wait)
        return os.path.exists(marker), to

    GRAND = ("import subprocess,sys\n"
             "subprocess.Popen([sys.executable,'-c','import time;time.sleep(2);open(\"marker.txt\",\"w\").write(\"x\")'])\n")
    # handshake version: the command does not exit before the grandchild proves it is running, so the
    # test cannot pass just because the grandchild was slow to start
    GRAND_STARTED = ("import subprocess,sys,time,os\n"
                     "code='import time;open(\"started.txt\",\"w\").write(\"x\");time.sleep(2);"
                     "open(\"marker.txt\",\"w\").write(\"x\")'\n"
                     "subprocess.Popen([sys.executable,'-c',code])\n"
                     "end=time.time()+30\n"
                     "while not os.path.exists('started.txt') and time.time()<end:\n"
                     "    time.sleep(0.05)\n")

    def test_grandchild_killed_when_command_exits(self):
        exists, to = self.marker_test(self.GRAND_STARTED + "sys.exit(0)\n", wait=4.0)
        self.assertTrue(os.path.exists(os.path.join(self.proj, "started.txt")), "the grandchild never ran")
        self.assertFalse(exists)

    def test_grandchild_killed_on_timeout(self):
        exists, to = self.marker_test(self.GRAND + "import time\ntime.sleep(60)\n", timeout=1)
        self.assertTrue(to)
        self.assertFalse(exists)

    @unittest.skipUnless(os.name == "nt", "Windows job object")
    def test_detached_grandchild_killed_on_windows(self):
        code = ("import subprocess,sys\n"
                "subprocess.Popen([sys.executable,'-c','import time;time.sleep(2);open(\"marker.txt\",\"w\").write(\"x\")'],"
                "creationflags=0x00000008|0x00000200)\n")
        exists, to = self.marker_test(code)
        self.assertFalse(exists)

    @unittest.skipUnless(os.name == "posix", "POSIX process group")
    def test_process_group_is_separate_on_posix(self):
        rc, text, to = self.run_py("import os;print(os.getpgid(0)==os.getpid())")
        self.assertEqual(text.strip(), "True")

    def test_two_level_grandchildren_killed_on_timeout(self):
        code = ("import subprocess,sys\n"
                "subprocess.Popen([sys.executable,'-c',\"import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c','import time;time.sleep(2);open(\\\"marker.txt\\\",\\\"w\\\").write(\\\"x\\\")']);"
                "time.sleep(60)\"])\n"
                "import time\ntime.sleep(60)\n")
        exists, to = self.marker_test(code, timeout=1)
        self.assertFalse(exists)

    def test_large_stderr_does_not_hang(self):
        t0 = time.time()
        rc, text, to = self.run_py("import sys;sys.stderr.write('e'*5000000)", cap=500)
        self.assertEqual(rc, 0)
        self.assertLess(time.time() - t0, 20)

    def test_invalid_utf8_output(self):
        rc, text, to = self.run_py("import sys;sys.stdout.buffer.write(b'ok \\xff\\xfe end')")
        self.assertIn("ok", text)
        self.assertIn("end", text)

    def test_python_executable_allowed_even_in_venv_like_path(self):
        rc, text, to = relay.run_argv([sys.executable, "-c", "print(1)"], self.proj)
        self.assertEqual(rc, 0)

    def test_expand_argv(self):
        got = relay.expand_argv(["{python}", "-c", "x", "{branch}", "{sha}"], {"branch": "feat/x", "sha": "a" * 40})
        self.assertEqual(got, [sys.executable, "-c", "x", "feat/x", "a" * 40])

    def test_expand_relay_placeholder(self):
        got = relay.expand_argv(["{relay}", "verify-authors"], {})
        self.assertEqual(got[0], sys.executable)
        self.assertTrue(got[1].endswith("relay.py"))

    def test_expand_missing_value_refused(self):
        with self.assertRaises(relay.RelayError):
            relay.expand_argv(["git", "{tag}"], {"tag": ""})


if __name__ == "__main__":
    unittest.main()
