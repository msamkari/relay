"""Shared test helpers. Everything runs in temp folders with RELAY_HOME relocated."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.dirname(HERE)
SCRIPT = os.path.join(PLUGIN, "scripts", "relay.py")

_spec = importlib.util.spec_from_file_location("relay_mod", SCRIPT)
relay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay)

NAME = "tester"
EMAIL = "t" + "@" + "example.invalid"
HAVE_GIT = shutil.which("git") is not None
ENV_CLEAR = ("RELAY_NO_SHIP", "RELAY_UNATTENDED", "RELAY_LOCK_STALE", "RELAY_LOCK_TIMEOUT")


def add_cases(cls, prefix, cases, fn):
    """One real test method per case, so a failure names the case."""
    for i, case in enumerate(cases):
        def make(c):
            def t(self):
                fn(self, c)
            return t
        setattr(cls, "test_%s_%03d" % (prefix, i), make(case))


def _rm_error(func, path, exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def make_link(target, link):
    """A symlink, or a junction on Windows. Returns False when neither can be made."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError, AttributeError):
        pass
    if os.name == "nt":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return r.returncode == 0
    return False


def drop_link(link):
    try:
        os.unlink(link)
    except OSError:
        try:
            os.rmdir(link)
        except OSError:
            pass


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="relaytest-"))
        self.proj = os.path.join(self.tmp, "proj")
        self.home = os.path.join(self.tmp, "home")
        os.mkdir(self.proj)
        self._cwd = os.getcwd()
        os.chdir(self.proj)
        p = mock.patch.dict(os.environ, {"RELAY_HOME": self.home})
        p.start()
        self.addCleanup(p.stop)
        for n in ENV_CLEAR:
            os.environ.pop(n, None)
        self.links = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        os.chdir(self._cwd)
        for l in self.links:
            drop_link(l)
        shutil.rmtree(self.tmp, onerror=_rm_error)

    # -- running the cli in-process
    def cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        old_in = sys.stdin
        if stdin is not None:
            sys.stdin = io.TextIOWrapper(io.BytesIO(stdin if isinstance(stdin, bytes) else stdin.encode("utf-8")))
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    rc = relay.main(list(argv))
                except SystemExit as e:
                    rc = e.code
        finally:
            sys.stdin = old_in
        return rc, out.getvalue(), err.getvalue()

    def sub(self, *argv, cwd=None, env=None, stdin=None):
        e = dict(os.environ)
        if env:
            e.update(env)
        r = subprocess.run([sys.executable, SCRIPT] + list(argv), cwd=cwd or self.proj, env=e,
                           input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")

    # -- registry helpers
    def init(self):
        rc, o, e = self.cli("init", "--yes")
        self.assertEqual(rc, 0, e)

    def add(self, iid="a1", text="do the thing", **kw):
        args = ["add", iid, "--title", kw.pop("title", "title " + iid), "--brief-text", text]
        for k, v in kw.items():
            if v is True:
                args.append("--" + k.replace("_", "-"))
            else:
                args += ["--" + k.replace("_", "-"), str(v)]
        return self.cli(*args)

    def reg_path(self):
        return os.path.join(self.proj, "Relay", "registry.json")

    def read_bytes(self, path):
        with open(path, "rb") as f:
            return f.read()

    def reg(self):
        with open(self.reg_path(), "rb") as f:
            return json.loads(f.read().decode("utf-8-sig"))

    def write_reg(self, obj):
        os.makedirs(os.path.dirname(self.reg_path()), exist_ok=True)
        with open(self.reg_path(), "wb") as f:
            f.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def raw_reg(self, data):
        os.makedirs(os.path.dirname(self.reg_path()), exist_ok=True)
        with open(self.reg_path(), "wb") as f:
            f.write(data)

    def write_file(self, rel, data):
        p = os.path.join(self.proj, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def item(self, **over):
        it = {"id": "a1", "title": "t", "kind": "task", "owner": "o", "brief": "Relay/briefs/a1.md",
              "status": "pending", "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z"}
        it.update(over)
        return it


def git(cwd, *args, check=True):
    r = subprocess.run(["git"] + list(args), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = r.stdout.decode("utf-8", "replace").strip()
    if check and r.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), out))
    return out


def init_repo(path, remote):
    """A repo with main, a feature branch feat/x (one commit ahead) and a local bare remote."""
    os.makedirs(path, exist_ok=True)
    git(path, "init", "-q")
    git(path, "symbolic-ref", "HEAD", "refs/heads/main")
    git(path, "config", "user.name", NAME)
    git(path, "config", "user.email", EMAIL)
    git(path, "config", "commit.gpgsign", "false")
    git(path, "config", "tag.gpgsign", "false")
    with open(os.path.join(path, "README.txt"), "w") as f:
        f.write("hello\n")
    with open(os.path.join(path, ".gitignore"), "w") as f:
        f.write("Relay/\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "base")
    os.makedirs(remote, exist_ok=True)
    git(remote, "init", "-q", "--bare")
    git(path, "remote", "add", "origin", remote)
    git(path, "push", "-q", "origin", "main")
    git(path, "checkout", "-q", "-b", "feat/x")
    with open(os.path.join(path, "feature.txt"), "w") as f:
        f.write("feature\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "feature")
