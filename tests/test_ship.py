"""Ship: config allow-list, trust, approve-ship, the refusal matrix, concurrency, verify-authors."""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from helpers import (Base, add_cases, relay, git, init_repo, HAVE_GIT, NAME, EMAIL, _rm_error, SCRIPT)

PYOK = ["{python}", "-c", "pass"]
PYFAIL = ["{python}", "-c", "import sys;sys.exit(3)"]


def base_ship():
    return {
        "repo": "owner/name", "target": "main", "remote": "origin",
        "commands": {
            "pr": [{"argv": ["git", "push", "origin", "{branch}"]}],
            "merge-ff": [{"argv": ["git", "switch", "main"]},
                         {"argv": ["git", "merge", "--ff-only", "{branch}"]},
                         {"argv": ["git", "push", "origin", "main"]}],
            "tag": [{"argv": ["git", "tag", "-a", "{tag}", "-m", "release", "{sha}"]},
                    {"argv": ["git", "push", "origin", "{tag}"]}],
            "release": [{"argv": ["gh", "release", "create", "{tag}", "--verify-tag", "--generate-notes"]}],
        },
        "checks": {
            "ci_green": {"argv": PYOK},
            "tests_green": {"argv": PYOK},
            "author_check": {"argv": ["{relay}", "verify-authors", "--base", "main", "--branch", "{branch}",
                                      "--name", NAME, "--email", EMAIL]},
        },
    }


def with_cmd(action, *steps):
    s = base_ship()
    s["commands"][action] = [{"argv": list(a)} for a in steps]
    return s


# ---------------------------------------------------------------- allow-list of command shapes
BAD_SHAPES = [
    ("pr", ["git", "push", "--force", "origin", "{branch}"]),
    ("pr", ["git", "push", "-f", "origin", "{branch}"]),
    ("pr", ["git", "push", "origin", "+{branch}"]),
    ("pr", ["git", "push", "origin", "{branch}:main"]),
    ("pr", ["git", "push", "origin", "main"]),
    ("pr", ["git", "push", "origin", "{branch}", "--force-with-lease"]),
    ("pr", ["git", "push", "--mirror", "origin"]),
    ("pr", ["git", "push", "--delete", "origin", "{branch}"]),
    ("pr", ["git", "push", "origin", ":{branch}"]),
    ("pr", ["git", "push", "origin", "--delete", "{branch}"]),
    ("pr", ["git", "branch", "-D", "{branch}"]),
    ("pr", ["git", "push", "upstream", "{branch}"]),
    ("pr", ["git", "-c", "core.hooksPath=x", "push", "origin", "{branch}"]),
    ("pr", ["git", "--git-dir=x", "push", "origin", "{branch}"]),
    ("pr", ["git", "push", "origin", "{branch}", "extra"]),
    ("pr", ["gh", "pr", "create", "--admin"]),
    ("pr", ["gh", "pr", "merge", "--admin"]),
    ("pr", ["gh", "pr", "merge", "--squash"]),
    ("pr", ["gh", "repo", "delete", "owner/name", "--yes"]),
    ("pr", ["gh", "repo", "edit", "--visibility", "public"]),
    ("pr", ["gh", "api", "-X", "DELETE", "repos/owner/name"]),
    ("pr", ["gh", "pr", "create", "--repo", "other/x"]),
    ("pr", ["gh", "pr", "create", "--base", "other"]),
    ("pr", ["gh", "pr", "create", "--head", "other"]),
    ("pr", ["gh", "pr", "create", "--web"]),
    ("pr", ["gh", "pr", "create", "--title"]),
    ("merge-ff", ["git", "merge", "{branch}"]),
    ("merge-ff", ["git", "merge", "--no-ff", "{branch}"]),
    ("merge-ff", ["git", "reset", "--hard"]),
    ("merge-ff", ["git", "push", "origin", "main", "--force"]),
    ("merge-ff", ["git", "push", "origin", "{branch}"]),
    ("merge-ff", ["git", "checkout", "other"]),
    ("merge-ff", ["git", "switch", "-c", "other"]),
    ("merge-ff", ["git", "rebase", "main"]),
    ("merge-ff", ["git", "push", "origin", "main:main"]),
    ("merge-ff", ["gh", "pr", "merge", "--rebase"]),
    ("tag", ["git", "tag", "-d", "{tag}"]),
    ("tag", ["git", "tag", "-f", "{tag}"]),
    ("tag", ["git", "tag", "{tag}", "-m", "x", "-f"]),
    ("tag", ["git", "push", "origin", "--tags"]),
    ("tag", ["git", "push", "--force", "origin", "{tag}"]),
    ("tag", ["git", "push", "origin", ":{tag}"]),
    ("tag", ["git", "tag", "v1.0.0"]),
    ("tag", ["git", "tag", "-a", "{tag}", "-m", "{branch}"]),
    ("release", ["gh", "release", "delete", "{tag}"]),
    ("release", ["gh", "release", "create", "{tag}", "--repo", "other/x"]),
    ("release", ["gh", "release", "create", "v1.0.0"]),
    ("release", ["gh", "release", "create", "{tag}", "--target", "other"]),
    ("release", ["gh", "release", "edit", "{tag}"]),
    ("release", ["gh", "release", "create", "{tag}", "--latest=false"]),
    ("release", ["git", "push", "origin", "{tag}"]),
    ("pr", ["cmd", "/c", "git push origin {branch}"]),
    ("pr", ["bash", "-c", "git push"]),
    ("pr", ["powershell", "-c", "git push"]),
    ("pr", ["env", "git", "push", "origin", "{branch}"]),
    ("pr", ["git.bat", "push"]),
    ("pr", ["./git", "push", "origin", "{branch}"]),
    ("pr", ["git.", "push", "origin", "{branch}"]),
    ("pr", ["python", "x.py"]),
    ("pr", ["npm", "publish"]),
    ("pr", ["{python}", "-c", "pass"]),
    ("pr", ["{relay}", "verify-authors"]),
    ("pr", ["curl", "http://x"]),
]

GOOD_SHAPES = [
    ("pr", ["git", "push", "origin", "{branch}"]),
    ("pr", ["git", "push", "-u", "origin", "{branch}"]),
    ("pr", ["git", "push", "--set-upstream", "origin", "{branch}"]),
    ("pr", ["gh", "pr", "create", "--fill"]),
    ("pr", ["gh", "pr", "create", "--fill", "--draft", "--base", "main", "--head", "{branch}", "--repo", "owner/name",
            "--title", "A title", "--body", "A body"]),
    ("merge-ff", ["git", "switch", "main"]),
    ("merge-ff", ["git", "checkout", "main"]),
    ("merge-ff", ["git", "fetch", "origin"]),
    ("merge-ff", ["git", "merge", "--ff-only", "{branch}"]),
    ("merge-ff", ["git", "push", "origin", "main"]),
    ("tag", ["git", "tag", "{tag}"]),
    ("tag", ["git", "tag", "-a", "{tag}", "-m", "msg", "{sha}"]),
    ("tag", ["git", "tag", "{tag}", "{sha}"]),
    ("tag", ["git", "push", "origin", "{tag}"]),
    ("release", ["gh", "release", "create", "{tag}"]),
    ("release", ["gh", "release", "create", "{tag}", "--title", "t", "--notes", "n", "--draft", "--prerelease",
                 "--verify-tag", "--generate-notes", "--target", "{sha}", "--repo", "owner/name"]),
]


def _bad_shape(self, c):
    action, argv = c
    s = with_cmd(action, argv)
    with self.assertRaises(relay.RelayError):
        relay.validate_ship(s)


def _good_shape(self, c):
    action, argv = c
    relay.validate_ship(with_cmd(action, argv))


def mutate(fn):
    s = base_ship()
    fn(s)
    return s


BAD_CONFIGS = [
    ("unknown_ship_key", mutate(lambda s: s.update(extra=1))),
    ("no_commands", mutate(lambda s: s.pop("commands"))),
    ("empty_commands", mutate(lambda s: s.update(commands={}))),
    ("unknown_action", mutate(lambda s: s["commands"].update({"delete-repo": [{"argv": ["git", "status"]}]}))),
    ("empty_steps", mutate(lambda s: s["commands"].update(pr=[]))),
    ("too_many_steps", mutate(lambda s: s["commands"].update(pr=[{"argv": ["git", "push", "origin", "{branch}"]}] * 6))),
    ("steps_not_list", mutate(lambda s: s["commands"].update(pr={"argv": ["git"]}))),
    ("step_extra_key", mutate(lambda s: s["commands"]["pr"][0].update(shell=True))),
    ("step_no_argv", mutate(lambda s: s["commands"].update(pr=[{"timeout": 5}]))),
    ("timeout_zero", mutate(lambda s: s["commands"]["pr"][0].update(timeout=0))),
    ("timeout_big", mutate(lambda s: s["commands"]["pr"][0].update(timeout=901))),
    ("timeout_bool", mutate(lambda s: s["commands"]["pr"][0].update(timeout=True))),
    ("max_output_small", mutate(lambda s: s["commands"]["pr"][0].update(max_output=5))),
    ("env_lowercase", mutate(lambda s: s["commands"]["pr"][0].update(env=["token"]))),
    ("pass_codes_range", mutate(lambda s: s["commands"]["pr"][0].update(pass_codes=[256]))),
    ("repo_space", mutate(lambda s: s.update(repo="a b"))),
    ("repo_traversal", mutate(lambda s: s.update(repo="../x"))),
    ("repo_three_parts", mutate(lambda s: s.update(repo="a/b/c"))),
    ("target_bad", mutate(lambda s: s.update(target="-x"))),
    ("remote_space", mutate(lambda s: s.update(remote="o r"))),
    ("remote_url", mutate(lambda s: s.update(remote="https://host/x"))),
    ("check_unknown_name", mutate(lambda s: s["checks"].update(lint={"argv": PYOK}))),
    ("check_git_push", mutate(lambda s: s["checks"].update(ci_green={"argv": ["git", "push", "origin", "main"]}))),
    ("check_git_branch", mutate(lambda s: s["checks"].update(ci_green={"argv": ["git", "branch", "-D", "x"]}))),
    ("check_git_dash_c", mutate(lambda s: s["checks"].update(ci_green={"argv": ["git", "-c", "x=y", "status"]}))),
    ("check_git_bare", mutate(lambda s: s["checks"].update(ci_green={"argv": ["git"]}))),
    ("check_gh_merge", mutate(lambda s: s["checks"].update(ci_green={"argv": ["gh", "pr", "merge", "1"]}))),
    ("check_gh_api", mutate(lambda s: s["checks"].update(ci_green={"argv": ["gh", "api", "x"]}))),
    ("check_gh_release_create", mutate(lambda s: s["checks"].update(ci_green={"argv": ["gh", "release", "create", "v1.0.0"]}))),
    ("check_shell", mutate(lambda s: s["checks"].update(ci_green={"argv": ["bash", "-c", "true"]}))),
    ("check_bat", mutate(lambda s: s["checks"].update(ci_green={"argv": ["run.bat"]}))),
    ("checks_not_object", mutate(lambda s: s.update(checks=[]))),
    ("protected_not_list", mutate(lambda s: s.update(protected="main"))),
    ("protected_bad_name", mutate(lambda s: s.update(protected=["a b"]))),
]


def _bad_config(self, c):
    with self.assertRaises(relay.RelayError):
        relay.validate_ship(c[1])


class ShapeTests(unittest.TestCase):
    def test_base_config_valid(self):
        relay.validate_ship(base_ship())

    def test_good_checks_shapes(self):
        for argv in (["git", "log", "--oneline"], ["git", "status", "--porcelain"], ["gh", "pr", "checks", "1"],
                     ["gh", "run", "list", "--limit", "1"], ["pytest", "-q"], ["{python}", "tests/run.py"],
                     ["git", "rev-parse", "HEAD"], ["gh", "pr", "view", "--json", "state"]):
            s = base_ship()
            s["checks"]["ci_green"] = {"argv": argv}
            relay.validate_ship(s)

    def test_no_force_or_delete_token_shapes_exist(self):
        """Walk every allowed shape: none contains a force/delete/visibility/admin spelling."""
        for action, argv in GOOD_SHAPES:
            for t in argv:
                low = t.casefold()
                for bad in ("--force", "-f", "--delete", "-d", "--admin", "--visibility", "--mirror", "--tags", "+"):
                    self.assertNotEqual(low, bad)
                self.assertFalse(low.startswith(("+", ":")))

    def test_protected_set(self):
        s = base_ship()
        s["protected"] = ["Develop"]
        self.assertEqual(relay.protected_branches(s), set(["develop", "main", "master"]))

    def test_branch_checks(self):
        s = base_ship()
        for good in ("feat/x", "fix-1", "a.b", "release/1.2"):
            self.assertEqual(relay.check_branch(good, s), good)
        for bad in ("main", "MAIN", "master", "-x", "a..b", "a b", "../x", "a/", "x.lock", "a//b", "@{u}", "a/.b",
                    "", "x;y", "a\nb", "feat/x.", "é"):
            with self.assertRaises(relay.RelayError, msg=repr(bad)):
                relay.check_branch(bad, s)


add_cases(ShapeTests, "bad_shape", BAD_SHAPES, _bad_shape)
add_cases(ShapeTests, "good_shape", GOOD_SHAPES, _good_shape)
add_cases(ShapeTests, "bad_config", BAD_CONFIGS, _bad_config)

# ---------------------------------------------------------------- repo fixture
TEMPLATE = {}


def setUpModule():
    if not HAVE_GIT:
        return
    d = os.path.realpath(tempfile.mkdtemp(prefix="relaytpl-"))
    init_repo(os.path.join(d, "work"), os.path.join(d, "remote.git"))
    TEMPLATE["dir"] = d


def tearDownModule():
    if TEMPLATE.get("dir"):
        shutil.rmtree(TEMPLATE["dir"], onerror=_rm_error)


@unittest.skipUnless(HAVE_GIT, "git is required")
class ShipBase(Base):
    def setUp(self):
        Base.setUp(self)
        os.chdir(self.tmp)
        shutil.rmtree(self.proj, onerror=_rm_error)
        shutil.copytree(os.path.join(TEMPLATE["dir"], "work"), self.proj)
        self.remote = os.path.join(self.tmp, "remote.git")
        shutil.copytree(os.path.join(TEMPLATE["dir"], "remote.git"), self.remote)
        os.chdir(self.proj)
        git(self.proj, "remote", "set-url", "origin", self.remote)
        self.init()
        self.cfg_path = os.path.join(self.proj, "Relay", "config.json")
        self.write_cfg(base_ship())
        rc, o, e = self.add("rel1", "ship the release", kind="release")
        self.assertEqual(rc, 0, e)

    def write_cfg(self, ship):
        with open(self.cfg_path, "w") as f:
            json.dump({"schema": 1, "ship": ship}, f)

    def edit_cfg(self, fn):
        with open(self.cfg_path) as f:
            d = json.load(f)
        fn(d["ship"])
        with open(self.cfg_path, "w") as f:
            json.dump(d, f)

    def trust(self):
        rc, o, e = self.cli("trust", "--yes")
        self.assertEqual(rc, 0, e)

    def approve(self, actions="pr", conds="", tag=None, branch="feat/x", item="rel1", yes=True, **kw):
        args = ["approve-ship", item, "--repo", kw.get("repo", "owner/name"), "--branch", branch,
                "--actions", actions, "--conditions", conds]
        if tag:
            args += ["--tag", tag]
        if kw.get("hours"):
            args += ["--hours", str(kw["hours"])]
        if kw.get("sha"):
            args += ["--sha", kw["sha"]]
        if yes:
            args.append("--yes")
        return self.cli(*args)

    def ready(self, actions="pr", conds="", tag=None, **kw):
        self.trust()
        rc, o, e = self.approve(actions, conds, tag, **kw)
        self.assertEqual(rc, 0, e)

    def ship(self, item="rel1"):
        return self.cli("ship", item)

    def tip(self, branch="feat/x"):
        return git(self.proj, "rev-parse", "refs/heads/" + branch)

    def remote_ref(self, ref):
        r = subprocess.run(["git", "rev-parse", "--verify", "--quiet", ref], cwd=self.remote,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return r.stdout.decode().strip() if r.returncode == 0 else None

    def approval_files(self):
        d = os.path.join(self.home, "approvals")
        return [os.path.join(d, n) for n in sorted(os.listdir(d))] if os.path.isdir(d) else []

    def load_approval(self):
        p = self.approval_files()[-1]
        return p, json.loads(self.read_bytes(p))

    def store_approval(self, rec, path=None, resign=True):
        if resign:
            rec["sig"] = relay.approval_mac(rec)
        p = path or os.path.join(self.home, "approvals", rec["nonce"] + ".json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump(rec, f)
        return p

    def forge(self, keep=False, **over):
        """A properly signed approval with some field changed (the secret is the user's own).
        It replaces the original approval file unless keep is set."""
        p, rec = self.load_approval()
        rec = dict(rec)
        rec["issued"] += 1
        rec["expires"] += 1
        rec.update(over)
        if "nonce" not in over:
            rec["nonce"] = os.urandom(16).hex()
        if not keep:
            os.unlink(p)
        return self.store_approval(rec)

    def log_events(self):
        p = os.path.join(self.proj, "Relay", "ship_log.jsonl")
        if not os.path.exists(p):
            return []
        return [json.loads(l) for l in self.read_bytes(p).decode().splitlines() if l.strip()]

    def refused(self, expect=None):
        rc, o, e = self.ship()
        self.assertEqual(rc, 2, (o, e))
        if expect:
            self.assertIn(expect, e)
        return o, e

    def nothing_shipped(self):
        self.assertIsNone(self.remote_ref("refs/heads/feat/x"))
        self.assertIsNone(self.remote_ref("refs/tags/v1.2.3"))
        self.assertEqual(self.remote_ref("refs/heads/main"), git(self.proj, "rev-parse", "refs/heads/main"))
        self.assertEqual(self.reg()["items"][0]["status"], "pending")


class TrustTests(ShipBase):
    def test_trust_dry_run_prints_commands_and_writes_nothing(self):
        rc, o, e = self.cli("trust")
        self.assertEqual(rc, 0, e)
        self.assertIn("git push origin {branch}", o)
        self.assertIn("program:", o)
        self.assertIn("NOT trusted", o)
        self.assertIn("Nothing was written", o)
        self.assertFalse(os.path.exists(self.home))

    def test_trust_yes_writes_to_home_only(self):
        self.trust()
        self.assertTrue(os.path.exists(os.path.join(self.home, "trust.json")))
        self.assertFalse(os.path.exists(os.path.join(self.home, "secret.key")))
        for dp, dn, fn in os.walk(self.proj):
            self.assertNotIn("trust.json", fn)
        rc, o, e = self.cli("trust")
        self.assertIn("already trusted", o)

    def test_trust_requires_ship_config(self):
        os.unlink(self.cfg_path)
        rc, o, e = self.cli("trust")
        self.assertEqual(rc, 1)

    def test_trust_changed_after_edit(self):
        self.trust()
        self.edit_cfg(lambda s: s["commands"]["pr"][0].update(timeout=99))
        rc, o, e = self.cli("trust")
        self.assertIn("NOT trusted (changed", o)

    def test_trust_prints_env_names_and_script_hash(self):
        def f(s):
            s["checks"]["ci_green"] = {"argv": ["{python}", "check.py"], "env": ["MY_TOKEN"]}
        self.write_file("check.py", "print(1)")
        self.edit_cfg(f)
        rc, o, e = self.cli("trust")
        self.assertIn("env names: MY_TOKEN", o)
        self.assertIn("script sha256", o)

    def test_trust_output_sanitised(self):
        rc, o, e = self.cli("trust")
        for ch in ("\x1b", "‮", "​"):
            self.assertNotIn(ch, o)

    def test_trust_refuses_unsafe_config(self):
        self.edit_cfg(lambda s: s["commands"]["pr"].append({"argv": ["git", "push", "--force", "origin", "{branch}"]}))
        rc, o, e = self.cli("trust", "--yes")
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(os.path.join(self.home, "trust.json")))

    def test_trust_per_project(self):
        self.trust()
        d = json.loads(self.read_bytes(os.path.join(self.home, "trust.json")))
        self.assertEqual(list(d["projects"]), [relay.root_key(self.proj)])

    def test_home_inside_project_refused(self):
        os.environ["RELAY_HOME"] = os.path.join(self.proj, "home")
        rc, o, e = self.cli("trust", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("RELAY_HOME", e)

    def test_home_relative_or_empty_refused(self):
        for v in ("rel/home", "", "  "):
            os.environ["RELAY_HOME"] = v
            rc, o, e = self.cli("trust", "--yes")
            self.assertEqual(rc, 1, repr(v))

    def test_programs_pinned_by_path(self):
        a = dict((l, p) for l, p, h, s in relay.resolved_programs(self.proj, base_ship()))
        self.assertTrue(a["action pr step 1"].endswith(("git", "git.exe")) or "git" in a["action pr step 1"].lower())


class ApproveTests(ShipBase):
    def test_requires_trust(self):
        rc, o, e = self.approve("pr")
        self.assertEqual(rc, 2)
        self.assertIn("not trusted", e)
        self.assertFalse(os.path.exists(os.path.join(self.home, "secret.key")))

    def test_plan_without_yes_writes_nothing(self):
        self.trust()
        rc, o, e = self.approve("pr", yes=False)
        self.assertEqual(rc, 0, e)
        self.assertIn("Nothing was written", o)
        self.assertIn(self.tip(), o)
        self.assertFalse(os.path.exists(os.path.join(self.home, "secret.key")))
        self.assertEqual(self.approval_files(), [])

    def test_yes_creates_secret_and_approval(self):
        self.ready("pr")
        key = self.read_bytes(os.path.join(self.home, "secret.key")).decode()
        self.assertRegex(key, r"^[0-9a-f]{64}$")
        p, rec = self.load_approval()
        self.assertEqual((rec["id"], rec["branch"], rec["sha"], rec["actions"]), ("rel1", "feat/x", self.tip(), ["pr"]))
        self.assertEqual(rec["expires"] - rec["issued"], 3600)
        self.assertEqual(rec["root"], relay.root_key(self.proj))

    def test_secret_never_in_project_or_output(self):
        self.trust()
        rc, o, e = self.approve("pr")
        key = self.read_bytes(os.path.join(self.home, "secret.key")).decode()
        self.assertNotIn(key, o + e)
        for dp, dn, fn in os.walk(self.proj):
            if ".git" in dp.split(os.sep):
                continue
            for n in fn:
                self.assertNotIn(key.encode(), self.read_bytes(os.path.join(dp, n)))

    def test_actions_conditions_required_matrix(self):
        self.trust()
        cases = [("merge-ff", "", False), ("merge-ff", "tests_green,author_check", False),
                 ("merge-ff", "ci_green,tests_green,author_check", True), ("tag", "tests_green", False),
                 ("tag", "tests_green,author_check", True), ("pr", "", True), ("release", "tests_green,author_check", False),
                 ("pr,merge-ff", "ci_green,tests_green,author_check", True)]
        for actions, conds, ok in cases:
            tag = "v1.2.3" if "tag" in actions or "release" in actions else None
            rc, o, e = self.approve(actions, conds, tag, yes=False)
            self.assertEqual(rc == 0, ok, (actions, conds, e))

    def test_tag_rules(self):
        self.trust()
        c = "tests_green,author_check"
        rc, o, e = self.approve("tag", c, None, yes=False)
        self.assertEqual(rc, 1)
        for bad in ("1.2", "v1.2.3.4", "release", "v1.2.3;x", "v1.2.3\n", "-v1.2.3", "v1.2.3-"):
            rc, o, e = self.approve("tag", c, bad, yes=False)
            self.assertEqual(rc, 1, bad)
        rc, o, e = self.approve("tag", c, "v1.2.3-rc.1", yes=False)
        self.assertEqual(rc, 0, e)
        rc, o, e = self.approve("pr", "", "v1.2.3", yes=False)
        self.assertEqual(rc, 1)

    def test_hours_limits(self):
        self.trust()
        for h, ok in ((24, True), (0.5, True), (25, False), (0, False), (-1, False), (1000, False)):
            rc, o, e = self.approve("pr", hours=h, yes=False) if h else self.cli(
                "approve-ship", "rel1", "--repo", "owner/name", "--branch", "feat/x", "--actions", "pr", "--hours", "0")
            self.assertEqual(rc == 0, ok, (h, e))
        rc, o, e = self.cli("approve-ship", "rel1", "--repo", "owner/name", "--branch", "feat/x", "--actions", "pr",
                            "--hours", "nan")
        self.assertEqual(rc, 1)

    def test_protected_branches_refused(self):
        self.trust()
        for b in ("main", "master", "MAIN"):
            rc, o, e = self.approve("pr", branch=b, yes=False)
            self.assertEqual(rc, 1, b)
        self.edit_cfg(lambda s: s.update(protected=["develop"]))
        self.trust()
        rc, o, e = self.approve("pr", branch="develop", yes=False)
        self.assertEqual(rc, 1)

    def test_bad_branch_names(self):
        self.trust()
        for b in ("-x", "a..b", "a b", "../x", "x;y", "a\nb", "feat/x.lock", "@{u}", "nonexistent-branch"):
            rc, o, e = self.approve("pr", branch=b, yes=False)
            self.assertEqual(rc, 1, repr(b))

    def test_repo_must_match_config(self):
        self.trust()
        rc, o, e = self.approve("pr", repo="other/name", yes=False)
        self.assertEqual(rc, 1)
        self.assertIn("does not match", e)

    def test_unknown_item(self):
        self.trust()
        rc, o, e = self.approve("pr", item="nope", yes=False)
        self.assertEqual(rc, 1)

    def test_item_id_case_must_be_exact(self):
        self.trust()
        rc, o, e = self.approve("pr", item="REL1", yes=False)
        self.assertEqual(rc, 1)

    def test_unknown_or_duplicate_actions_and_conditions(self):
        self.trust()
        for actions, conds in (("delete", ""), ("pr,pr", ""), ("", ""), ("force-push", ""), ("pr", "lint"),
                               ("pr", "ci_green,ci_green"), ("PR", "")):
            rc, o, e = self.approve(actions, conds, yes=False)
            self.assertEqual(rc, 1, (actions, conds))

    def test_action_without_pinned_commands(self):
        self.edit_cfg(lambda s: s["commands"].pop("pr"))
        self.trust()
        rc, o, e = self.approve("pr", yes=False)
        self.assertEqual(rc, 1)

    def test_condition_without_pinned_check(self):
        self.edit_cfg(lambda s: s["checks"].pop("tests_green"))
        self.trust()
        rc, o, e = self.approve("merge-ff", "ci_green,tests_green,author_check", yes=False)
        self.assertEqual(rc, 1)

    def test_sha_must_match_tip(self):
        self.trust()
        rc, o, e = self.approve("pr", sha="0" * 40, yes=False)
        self.assertEqual(rc, 1)
        rc, o, e = self.approve("pr", sha=self.tip(), yes=False)
        self.assertEqual(rc, 0, e)
        rc, o, e = self.approve("pr", sha=self.tip()[:12], yes=False)
        self.assertEqual(rc, 1)
        rc, o, e = self.approve("pr", sha=self.tip().upper(), yes=False)
        self.assertEqual(rc, 1)

    def test_changed_config_after_trust_refuses_approve(self):
        self.trust()
        self.edit_cfg(lambda s: s["commands"]["pr"][0].update(timeout=77))
        rc, o, e = self.approve("pr", yes=False)
        self.assertEqual(rc, 2)

    def test_kill_switch(self):
        self.trust()
        for name, val in (("RELAY_NO_SHIP", "1"), ("RELAY_NO_SHIP", "0"), ("RELAY_NO_SHIP", "anything"),
                          ("RELAY_UNATTENDED", "1")):
            os.environ[name] = val
            try:
                rc, o, e = self.approve("pr")
                self.assertEqual(rc, 2, (name, val))
                rc, o, e = self.cli("trust", "--yes")
                self.assertEqual(rc, 2, (name, val))
            finally:
                del os.environ[name]
        self.assertEqual(self.approval_files(), [])

    def test_kill_switch_empty_value_is_unset(self):
        self.trust()
        os.environ["RELAY_NO_SHIP"] = ""
        try:
            rc, o, e = self.approve("pr")
            self.assertEqual(rc, 0, e)
        finally:
            del os.environ["RELAY_NO_SHIP"]

    def test_trust_dry_run_works_under_kill_switch(self):
        os.environ["RELAY_NO_SHIP"] = "1"
        try:
            rc, o, e = self.cli("trust")
            self.assertEqual(rc, 0, e)
        finally:
            del os.environ["RELAY_NO_SHIP"]

    def test_damaged_secret_refused(self):
        self.ready("pr")
        with open(os.path.join(self.home, "secret.key"), "w") as f:
            f.write("not-hex")
        rc, o, e = self.approve("pr")
        self.assertEqual(rc, 1)

    def test_approval_file_not_in_project(self):
        self.ready("pr")
        for dp, dn, fn in os.walk(self.proj):
            for n in fn:
                self.assertFalse(n.endswith(".json") and "approvals" in dp)


class ShipTests(ShipBase):
    # ---- happy paths
    def test_pr_happy_path(self):
        self.ready("pr")
        rc, o, e = self.ship()
        self.assertEqual(rc, 0, (o, e))
        self.assertEqual(self.remote_ref("refs/heads/feat/x"), self.tip())
        self.assertEqual(self.reg()["items"][0]["status"], "done")
        self.assertIsNone(self.remote_ref("refs/tags/v1.2.3"))
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.tip())

    def test_merge_ff_happy_path(self):
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertEqual(rc, 0, (o, e))
        self.assertEqual(self.remote_ref("refs/heads/main"), self.tip())
        self.assertIsNone(self.remote_ref("refs/heads/feat/x"))
        self.assertIn("check ci_green: ok", o)
        self.assertIn("check author_check: ok", o)

    def test_tag_happy_path(self):
        self.ready("tag", "tests_green,author_check", tag="v1.2.3")
        rc, o, e = self.ship()
        self.assertEqual(rc, 0, (o, e))
        self.assertEqual(self.remote_ref("refs/tags/v1.2.3^{commit}"), self.tip())

    def test_combined_actions_in_canonical_order(self):
        self.ready("tag,merge-ff,pr", "ci_green,tests_green,author_check", tag="v1.2.3")
        rc, o, e = self.ship()
        self.assertEqual(rc, 0, (o, e))
        steps = [ev["step"] for ev in self.log_events() if ev["event"] == "step_start"]
        actions = [s.split()[1] for s in steps if s.startswith("action")]
        self.assertEqual(actions, ["pr", "merge-ff", "merge-ff", "merge-ff", "tag", "tag"])
        self.assertEqual(self.remote_ref("refs/heads/main"), self.tip())

    def test_only_approved_actions_run(self):
        self.ready("pr")
        self.ship()
        self.assertIsNone(self.remote_ref("refs/tags/v1.2.3"))
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.tip())
        self.assertTrue(all("merge-ff" not in ev.get("step", "") and "tag" not in ev.get("step", "")
                            for ev in self.log_events()))

    def test_checks_run_before_actions(self):
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        self.ship()
        order = [ev["step"] for ev in self.log_events() if ev["event"] == "step_start"]
        first_action = min(i for i, s in enumerate(order) if s.startswith("action"))
        last_check = max(i for i, s in enumerate(order) if s.startswith("check"))
        self.assertLess(last_check, first_action)

    def test_placeholders_are_substituted(self):
        self.ready("pr")
        calls = []
        real = relay.run_argv

        def spy(argv, *a, **k):
            calls.append(list(argv))
            return real(argv, *a, **k)
        with mock.patch.object(relay, "run_argv", spy):
            self.ship()
        pushes = [c[-3:] for c in calls if "push" in c]
        self.assertEqual(pushes, [["push", "origin", "feat/x"]])
        self.assertTrue(all(c[1] == "-c" and c[2].startswith("core.hooksPath=") for c in calls if c[0] == "git"))

    def test_release_action_argv_with_mocked_gh(self):
        self.ready("release", "ci_green,tests_green,author_check", tag="v1.2.3")
        calls = []
        real = relay.run_argv

        def fake(argv, root, *a, **k):
            if argv[0] == "gh":
                calls.append(list(argv))
                return 0, "created", False
            return real(argv, root, *a, **k)
        with mock.patch.object(relay, "run_argv", fake):
            rc, o, e = self.ship()
        self.assertEqual(rc, 0, (o, e))
        self.assertEqual(calls, [["gh", "release", "create", "v1.2.3", "--verify-tag", "--generate-notes"]])

    def test_log_written_and_ascii(self):
        self.ready("pr")
        self.ship()
        raw = self.read_bytes(os.path.join(self.proj, "Relay", "ship_log.jsonl"))
        raw.decode("ascii")
        evs = [json.loads(l) for l in raw.decode().splitlines()]
        self.assertEqual([e["event"] for e in evs][0], "start")
        self.assertEqual([e["event"] for e in evs][-1], "done")
        self.assertTrue(all("ts" in e for e in evs))
        self.assertEqual(evs[0]["sha"], self.tip())

    def test_single_use(self):
        self.ready("pr")
        self.assertEqual(self.ship()[0], 0)
        self.refused("no unused approval")

    def test_registry_marked_done_with_note(self):
        self.ready("pr")
        self.ship()
        it = self.reg()["items"][0]
        self.assertEqual((it["status"], it["usage_note"]), ("done", "shipped: pr"))

    # ---- refusals
    def test_no_approval(self):
        self.trust()
        self.refused("no unused approval")
        self.nothing_shipped()

    def test_no_trust(self):
        self.ready("pr")
        os.unlink(os.path.join(self.home, "trust.json"))
        self.refused("not trusted")
        self.nothing_shipped()

    def test_trust_for_other_project_does_not_count(self):
        self.ready("pr")
        d = json.loads(self.read_bytes(os.path.join(self.home, "trust.json")))
        d["projects"] = {"/other/project": list(d["projects"].values())[0]}
        with open(os.path.join(self.home, "trust.json"), "w") as f:
            json.dump(d, f)
        self.refused("not trusted")

    def test_expired(self):
        self.ready("pr", hours=1)
        later = relay.now_epoch() + 3 * 3600
        with mock.patch.object(relay, "now_epoch", return_value=later):
            o, e = self.refused("expired")
        self.nothing_shipped()

    def test_not_yet_expired_still_works(self):
        self.ready("pr", hours=2)
        with mock.patch.object(relay, "now_epoch", return_value=relay.now_epoch() + 3600):
            rc, o, e = self.ship()
        self.assertEqual(rc, 0, e)

    def test_other_sha_branch_moved(self):
        self.ready("pr")
        git(self.proj, "commit", "-q", "--allow-empty", "-m", "another")
        self.refused("branch moved")
        self.nothing_shipped()

    def test_branch_deleted_after_approval(self):
        self.ready("pr")
        git(self.proj, "checkout", "-q", "main")
        git(self.proj, "branch", "-D", "feat/x")
        self.refused()

    def test_other_repo(self):
        self.ready("pr")
        self.forge(repo="other/name")
        self.refused("another repo")
        self.nothing_shipped()

    def test_other_project_folder(self):
        self.ready("pr")
        p = self.forge(root="/some/other/folder")
        # the newest approval for THIS folder is still the original, which is valid: remove it
        for f in self.approval_files():
            if f != p:
                os.unlink(f)
        self.refused()

    def test_other_item(self):
        self.ready("pr")
        self.add("rel2", "other")
        rc, o, e = self.ship("rel2")
        self.assertEqual(rc, 2)
        self.assertIn("no unused approval", e)
        self.nothing_shipped()

    def test_forged_item_in_approval(self):
        self.ready("pr")
        self.add("rel2", "other")
        self.forge(keep=True, id="rel2")
        # now rel2 has a validly signed approval; rel1 still works with its own
        rc, o, e = self.ship("rel1")
        self.assertEqual(rc, 0, e)

    def test_other_action_not_in_approval_not_run(self):
        self.ready("pr")
        self.ship()
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.tip())

    def test_other_action_edited_in_file(self):
        self.ready("pr")
        p, rec = self.load_approval()
        rec["actions"] = ["pr", "merge-ff"]
        self.store_approval(rec, path=p, resign=False)
        self.refused("signature")
        self.nothing_shipped()

    def test_edited_fields_break_signature(self):
        self.ready("pr")
        p, rec0 = self.load_approval()
        edits = {"branch": "feat/y", "sha": "1" * 40, "expires": rec0["expires"] + 10, "issued": rec0["issued"] - 5,
                 "id": "rel1", "tag": "v9.9.9", "conditions": ["ci_green"], "trust": "2" * 64,
                 "repo": "owner/other", "root": "/x", "nonce": "3" * 32}
        for k, v in edits.items():
            rec = dict(rec0)
            rec[k] = v
            if rec == rec0:
                continue
            self.store_approval(rec, path=p, resign=False)
            if k in ("root", "nonce"):
                # these change which file/folder matches; the verdict must still be a refusal
                rc, o, e = self.ship()
                self.assertEqual(rc, 2, k)
            else:
                self.refused("signature")
        self.nothing_shipped()

    def test_forged_signature_random(self):
        self.ready("pr")
        p, rec = self.load_approval()
        rec["sig"] = os.urandom(32).hex()
        self.store_approval(rec, path=p, resign=False)
        self.refused("signature")
        self.nothing_shipped()

    def test_forged_signature_other_secret(self):
        import hmac
        import hashlib
        self.ready("pr")
        p, rec = self.load_approval()
        body = dict((k, v) for k, v in rec.items() if k != "sig")
        msg = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        rec["sig"] = hmac.new(b"x" * 32, msg, hashlib.sha256).hexdigest()
        self.store_approval(rec, path=p, resign=False)
        self.refused("signature")

    def test_forged_signature_malformed(self):
        self.ready("pr")
        p, rec = self.load_approval()
        for sig in ("", "zz", "A" * 64, None, 5, "0" * 63):
            rec["sig"] = sig
            self.store_approval(rec, path=p, resign=False)
            self.refused()
        self.nothing_shipped()

    def test_unknown_field_in_approval(self):
        self.ready("pr")
        p, rec = self.load_approval()
        rec["admin"] = True
        self.store_approval(rec, path=p, resign=True)
        self.refused("damaged or edited")

    def test_missing_secret(self):
        self.ready("pr")
        os.unlink(os.path.join(self.home, "secret.key"))
        self.refused("signature")

    def test_changed_commands_after_trust(self):
        self.ready("pr")
        self.edit_cfg(lambda s: s["commands"]["pr"][0].update(timeout=77))
        self.refused("changed since you trusted")
        self.nothing_shipped()

    def test_added_step_after_trust(self):
        self.ready("pr")
        self.edit_cfg(lambda s: s["commands"]["pr"].append({"argv": ["git", "push", "-u", "origin", "{branch}"]}))
        self.refused("changed since you trusted")

    def test_changed_check_after_trust(self):
        self.ready("pr")
        self.edit_cfg(lambda s: s["checks"]["ci_green"].update(argv=["{python}", "-c", "print(1)"]))
        self.refused("changed since you trusted")

    def test_script_edit_after_trust(self):
        self.write_file("check.py", "import sys\nsys.exit(0)\n")
        self.edit_cfg(lambda s: s["checks"].update(tests_green={"argv": ["{python}", "check.py"]}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        self.write_file("check.py", "import sys\nsys.exit(0)  # edited\n")
        self.refused("changed since you trusted")
        self.nothing_shipped()

    def test_script_replaced_during_run_via_trust_recheck(self):
        """A check that edits the config while it runs is caught before any action."""
        code = ("import json;p='Relay/config.json';d=json.load(open(p));"
                "d['ship']['commands']['pr'][0]['timeout']=5;json.dump(d,open(p,'w'))")
        self.edit_cfg(lambda s: s["checks"].update(tests_green={"argv": ["{python}", "-c", code]}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2, (o, e))
        self.assertIn("changed while the checks ran", e)
        self.assertIsNone(self.remote_ref("refs/heads/feat/x"))
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.tip())

    def test_branch_moves_during_checks(self):
        code = "import subprocess;subprocess.run(['git','commit','-q','--allow-empty','-m','sneaky'])"
        self.edit_cfg(lambda s: s["checks"].update(tests_green={"argv": ["{python}", "-c", code]}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2, (o, e))
        self.assertIn("moved while the checks ran", e)
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.tip())

    def test_failed_check_aborts_everything(self):
        self.edit_cfg(lambda s: s["checks"].update(tests_green={"argv": PYFAIL}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2)
        self.assertIn("condition tests_green failed", e)
        self.assertEqual(self.remote_ref("refs/heads/main"), git(self.proj, "rev-parse", "refs/heads/main"))
        self.assertTrue(any(ev["event"] == "abort" for ev in self.log_events()))
        self.refused("no unused approval")  # the approval was consumed

    def test_check_timeout_aborts(self):
        self.edit_cfg(lambda s: s["checks"].update(
            ci_green={"argv": ["{python}", "-c", "import time;time.sleep(30)"], "timeout": 1}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2)
        self.assertIn("timed out", o)

    def test_check_program_missing_aborts(self):
        self.edit_cfg(lambda s: s["checks"].update(ci_green={"argv": ["definitely-not-installed-xyz"]}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2)

    def test_author_check_fails_for_wrong_author(self):
        git(self.proj, "-c", "user.name=someone", "-c", "user.email=" + "x" + "@" + "example.invalid",
            "commit", "-q", "--allow-empty", "-m", "by someone else")
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2)
        self.assertIn("author_check", e)
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.tip())

    def test_failing_action_step_stops_later_steps(self):
        git(self.proj, "remote", "set-url", "origin", os.path.join(self.tmp, "no-such-remote"))
        self.ready("pr,tag", "tests_green,author_check", tag="v1.2.3")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2)
        self.assertIn("action pr step 1 failed", e)
        ran = [ev["step"] for ev in self.log_events() if ev["event"] == "step_start"]
        self.assertFalse(any(s.startswith("action tag") for s in ran))
        self.assertEqual(self.reg()["items"][0]["status"], "pending")

    def test_newest_invalid_approval_blocks_older_valid(self):
        self.ready("pr")
        p, rec = self.load_approval()
        bad = dict(rec)
        bad["nonce"] = os.urandom(16).hex()
        bad["issued"] = rec["issued"] + 5
        bad["sig"] = "0" * 64
        self.store_approval(bad, resign=False)
        self.refused("signature")
        self.nothing_shipped()

    def test_future_dated_approval(self):
        self.ready("pr")
        now = int(relay.now_epoch())
        self.forge(issued=now + 7200, expires=now + 10800)
        self.refused("future")

    def test_lifetime_over_24h(self):
        self.ready("pr")
        now = int(relay.now_epoch())
        self.forge(issued=now, expires=now + 25 * 3600)
        self.refused("lifetime")

    def test_forged_with_protected_branch(self):
        self.ready("pr")
        self.forge(branch="main")
        self.refused()

    def test_forged_with_unpinned_action(self):
        self.ready("pr")
        self.edit_cfg(lambda s: None)
        self.forge(actions=["pr", "merge-ff"], conditions=["ci_green", "tests_green", "author_check"])
        # merge-ff has pinned commands, so this is a valid signed approval: it runs both, as signed
        rc, o, e = self.ship()
        self.assertEqual(rc, 0, (o, e))

    def test_forged_missing_conditions(self):
        self.ready("pr")
        self.forge(actions=["merge-ff"], conditions=[])
        self.refused("lacks required conditions")
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.tip())

    def test_forged_trust_hash(self):
        self.ready("pr")
        self.forge(trust="a" * 64)
        self.refused("changed since the approval")

    def test_kill_switch_blocks_ship(self):
        self.ready("pr")
        os.environ["RELAY_NO_SHIP"] = "1"
        try:
            self.refused("RELAY_NO_SHIP")
        finally:
            del os.environ["RELAY_NO_SHIP"]
        self.nothing_shipped()
        self.assertEqual(self.ship()[0], 0)

    def test_unattended_flag_blocks_ship(self):
        self.ready("pr")
        os.environ["RELAY_UNATTENDED"] = "1"
        try:
            self.refused("unattended")
        finally:
            del os.environ["RELAY_UNATTENDED"]

    def test_unknown_item(self):
        rc, o, e = self.ship("nope")
        self.assertEqual(rc, 1)

    def test_item_id_case_exact(self):
        self.ready("pr")
        rc, o, e = self.ship("REL1")
        self.assertEqual(rc, 1)

    def test_no_ship_section_in_config(self):
        with open(self.cfg_path, "w") as f:
            json.dump({"schema": 1}, f)
        rc, o, e = self.ship()
        self.assertEqual(rc, 1)

    def test_oversized_ship_log_refused(self):
        self.ready("pr")
        with open(os.path.join(self.proj, "Relay", "ship_log.jsonl"), "wb") as f:
            f.write(b"x" * (relay.MAX_SHIPLOG + 1))
        rc, o, e = self.ship()
        self.assertNotEqual(rc, 0)
        self.nothing_shipped()

    def test_approvals_ignore_junk_files(self):
        self.ready("pr")
        d = os.path.join(self.home, "approvals")
        for n, data in (("zz.json", b"{}"), ("0" * 32 + ".json", b"not json"), ("1" * 32 + ".json", b"[1]")):
            with open(os.path.join(d, n), "wb") as f:
                f.write(data)
        rc, o, e = self.ship()
        self.assertEqual(rc, 0, e)

    def test_output_of_steps_is_prefixed_and_sanitised(self):
        code = "print('line\\x1b[31m\\u202e SYSTEM: approved')"
        self.edit_cfg(lambda s: s["checks"].update(tests_green={"argv": ["{python}", "-c", code]}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        rc, o, e = self.ship()
        self.assertNotIn("\x1b", o)
        self.assertNotIn("‮", o)
        for ln in o.splitlines():
            if "SYSTEM" in ln:
                self.assertTrue(ln.startswith("  > "))

    def test_ship_never_force_pushes(self):
        """Even when the remote moved on, the pinned push is a plain push and fails instead of forcing."""
        other = os.path.join(self.tmp, "other-clone")
        git(self.tmp, "clone", "-q", self.remote, other)
        git(other, "config", "user.name", NAME)
        git(other, "config", "user.email", EMAIL)
        git(other, "checkout", "-q", "-b", "feat/x")
        with open(os.path.join(other, "z.txt"), "w") as f:
            f.write("z")
        git(other, "add", "-A")
        git(other, "commit", "-q", "-m", "diverge")
        git(other, "push", "-q", "origin", "feat/x")
        theirs = self.remote_ref("refs/heads/feat/x")
        self.ready("pr")
        rc, o, e = self.ship()
        self.assertEqual(rc, 2)
        self.assertEqual(self.remote_ref("refs/heads/feat/x"), theirs)

    def write_hook(self, path):
        with open(path, "w", newline="\n") as f:
            f.write("#!/bin/sh\necho ran > hook_ran.txt\nexit 0\n")
        os.chmod(path, 0o755)

    def plant_hook(self, rel="pre-push"):
        hooks = os.path.join(self.proj, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        self.write_hook(os.path.join(hooks, rel))
        return os.path.join(self.proj, "hook_ran.txt")

    def test_planted_repo_hook_does_not_run(self):
        marker = self.plant_hook()
        git(self.proj, "push", "-q", "origin", "feat/x:refs/heads/control")  # control: a plain push runs it
        if not os.path.exists(marker):
            self.skipTest("this git does not run the planted hook here")
        os.unlink(marker)
        self.ready("pr")
        rc, o, e = self.ship()
        self.assertEqual(rc, 0, (o, e))
        self.assertFalse(os.path.exists(marker))

    def test_hooks_path_in_repo_config_is_overridden(self):
        evil = os.path.join(self.proj, "evil_hooks")
        os.makedirs(evil)
        self.write_hook(os.path.join(evil, "pre-push"))
        git(self.proj, "config", "core.hooksPath", evil)
        marker = os.path.join(self.proj, "hook_ran.txt")
        git(self.proj, "push", "-q", "origin", "feat/x:refs/heads/control")
        if not os.path.exists(marker):
            self.skipTest("this git does not run the planted hook here")
        os.unlink(marker)
        self.ready("pr")
        self.assertEqual(self.ship()[0], 0)
        self.assertFalse(os.path.exists(marker))

    def test_git_prefix_disables_hooks_and_fsmonitor(self):
        pre = relay.git_prefix(self.proj)
        self.assertEqual(pre[0], "-c")
        self.assertTrue(pre[1].startswith("core.hooksPath="))
        self.assertIn(self.home.replace("\\", "/"), pre[1])
        self.assertIn("core.fsmonitor=false", pre)
        self.assertEqual(relay.with_git_prefix(self.proj, ["python", "x"]), ["python", "x"])
        self.assertEqual(relay.with_git_prefix(self.proj, ["git", "status"])[-1], "status")

    def test_lock_not_held_during_ship(self):
        self.ready("pr")
        self.ship()
        self.assertFalse(os.path.exists(os.path.join(self.proj, "Relay", relay.LOCK_NAME)))

    def test_secret_like_output_not_logged(self):
        code = "print('k ' + 'gh' + 'p_' + 'Q'*36)"
        self.edit_cfg(lambda s: s["checks"].update(tests_green={"argv": ["{python}", "-c", code]}))
        self.ready("merge-ff", "ci_green,tests_green,author_check")
        self.ship()
        raw = self.read_bytes(os.path.join(self.proj, "Relay", "ship_log.jsonl")).decode()
        self.assertNotIn("ghp_", raw)


class ShipProcessTests(ShipBase):
    def test_two_concurrent_ships_exactly_one_runs(self):
        self.ready("pr")
        env = dict(os.environ)
        procs = [subprocess.Popen([sys.executable, SCRIPT, "ship", "rel1"], cwd=self.proj, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)]
        rcs = sorted(p.wait() for p in procs)
        for p in procs:
            p.stdout.close()
            p.stderr.close()
        self.assertEqual(rcs.count(0), 1, rcs)
        self.assertEqual(self.remote_ref("refs/heads/feat/x"), self.tip())

    def test_cli_exit_codes(self):
        rc, o, e = self.sub("ship", "rel1")
        self.assertEqual(rc, 2)
        self.assertTrue(e.startswith("refused:"))


# ---------------------------------------------------------------- verify-authors
@unittest.skipUnless(HAVE_GIT, "git is required")
class AuthorTests(Base):
    def setUp(self):
        Base.setUp(self)
        init_repo(self.proj, os.path.join(self.tmp, "r.git"))

    def va(self, *extra, name=NAME, email=EMAIL):
        return self.cli("verify-authors", "--base", "main", "--branch", "feat/x", "--name", name, "--email", email, *extra)

    def commit(self, msg, name=NAME, email=EMAIL, committer=None):
        env = dict(os.environ)
        c = committer or (name, email)
        env.update({"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": c[0],
                    "GIT_COMMITTER_EMAIL": c[1]})
        r = subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", msg], cwd=self.proj, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_pass(self):
        rc, o, e = self.va()
        self.assertEqual(rc, 0, (o, e))
        self.assertIn("1 commit", o)

    def test_wrong_author(self):
        self.commit("x", name="other", email="o" + "@" + "example.invalid")
        rc, o, e = self.va()
        self.assertEqual(rc, 2)
        self.assertIn("author", o)

    def test_wrong_committer(self):
        self.commit("x", committer=("other", "o" + "@" + "example.invalid"))
        rc, o, e = self.va()
        self.assertEqual(rc, 2)
        self.assertIn("committer", o)

    def test_co_authored_by_trailer(self):
        self.commit("x\n\nCo-Authored-By: Someone <s" + "@" + "example.invalid>")
        rc, o, e = self.va()
        self.assertEqual(rc, 2)
        self.assertIn("trailer", o)

    def test_trailer_case_insensitive(self):
        self.commit("x\n\nco-authored-by: Someone <s" + "@" + "example.invalid>")
        self.assertEqual(self.va()[0], 2)

    def test_tool_footer(self):
        self.commit("x\n\nGenerated with [Claude Code](https://example.invalid)")
        rc, o, e = self.va()
        self.assertEqual(rc, 2)
        self.assertIn("footer", o)

    def test_session_link(self):
        self.commit("x\n\nhttps://claude.ai/code/session_abcdef123456")
        rc, o, e = self.va()
        self.assertEqual(rc, 2)
        self.assertIn("session link", o)

    def test_message_text_never_printed(self):
        self.commit("MARKER-TEXT-123\n\nCo-Authored-By: S <s" + "@" + "example.invalid>")
        rc, o, e = self.va()
        self.assertNotIn("MARKER-TEXT-123", o + e)

    def test_no_commits_is_an_error(self):
        rc, o, e = self.cli("verify-authors", "--base", "feat/x", "--branch", "feat/x", "--name", NAME, "--email", EMAIL)
        self.assertEqual(rc, 1)

    def test_all_flag_sees_other_branches(self):
        git(self.proj, "checkout", "-q", "-b", "other")
        self.commit("x", name="intruder", email="i" + "@" + "example.invalid")
        git(self.proj, "checkout", "-q", "feat/x")
        self.assertEqual(self.va()[0], 0)
        self.assertEqual(self.va("--all")[0], 2)

    def test_bad_ref_names(self):
        for bad in ("-x", "a..b", "a b", "x;y"):
            rc, o, e = self.cli("verify-authors", "--base", bad, "--branch", "feat/x", "--name", NAME, "--email", EMAIL)
            self.assertEqual(rc, 1, bad)

    def test_unknown_ref(self):
        rc, o, e = self.cli("verify-authors", "--base", "main", "--branch", "nope", "--name", NAME, "--email", EMAIL)
        self.assertEqual(rc, 1)

    def test_wrong_expected_identity(self):
        rc, o, e = self.va(name="somebody", email="s" + "@" + "example.invalid")
        self.assertEqual(rc, 2)

    def test_many_bad_commits_listing_capped(self):
        for i in range(60):
            self.commit("c%d" % i, name="other", email="o" + "@" + "example.invalid")
        rc, o, e = self.va()
        self.assertEqual(rc, 2)
        self.assertLess(len(o.splitlines()), 60)


if __name__ == "__main__":
    unittest.main()
