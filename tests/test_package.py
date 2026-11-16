"""Package layout, manifest, skills, hygiene and portability checks."""
import ast
import json
import os
import re
import sys
import unittest

from helpers import PLUGIN, SCRIPT, relay, Base

READ_ONLY = ["list", "next", "brief", "resume-plan", "check-usage"]


def rb(path):
    with open(path, "rb") as f:
        return f.read()


def read(*parts):
    with open(os.path.join(PLUGIN, *parts), "rb") as f:
        return f.read().decode("utf-8")


def tracked_text_files():
    res = []
    for dp, dn, fn in os.walk(PLUGIN):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__")]
        for n in fn:
            if n.endswith((".pyc", ".tmp")):
                continue
            res.append(os.path.join(dp, n))
    return res


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.m = json.loads(read(".claude-plugin", "plugin.json"))

    def test_fields(self):
        self.assertEqual(self.m["name"], "relay")
        self.assertEqual(self.m["version"], "0.1.0")
        self.assertEqual(self.m["license"], "MIT")
        self.assertEqual(self.m["author"]["name"], "Mohammad Samkari")

    def test_no_placeholder_icon_key(self):
        self.assertNotIn("icon", self.m)

    def test_version_matches_script_and_changelog(self):
        self.assertEqual(self.m["version"], relay.VERSION)
        self.assertIn("## 0.1.0", read("CHANGELOG.md"))

    def test_official_layout(self):
        self.assertTrue(os.path.isfile(os.path.join(PLUGIN, ".claude-plugin", "plugin.json")))
        self.assertEqual(os.listdir(os.path.join(PLUGIN, ".claude-plugin")), ["plugin.json"])
        for d in ("skills", "scripts", "tests", "examples"):
            self.assertTrue(os.path.isdir(os.path.join(PLUGIN, d)), d)
        self.assertFalse(os.path.exists(os.path.join(PLUGIN, ".claude-plugin", "skills")))

    def test_license_is_mit(self):
        self.assertIn("MIT License", read("LICENSE"))

    def test_readmes_exist(self):
        for n in ("README.md", "README.ar.md", "CHANGELOG.md"):
            self.assertTrue(len(read(n)) > 500, n)

    def test_ci_workflow(self):
        ci = read(".github", "workflows", "ci.yml")
        self.assertIn("unittest discover", ci)
        self.assertIn("plugin validate", ci)
        self.assertIn("3.8", ci)

    def test_no_third_party_dependency_files(self):
        for n in ("package.json", "requirements.txt", "pyproject.toml", "setup.py"):
            self.assertFalse(os.path.exists(os.path.join(PLUGIN, n)), n)


class SkillTests(unittest.TestCase):
    def front(self, name):
        text = read("skills", name, "SKILL.md")
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        self.assertTrue(m, name)
        d = {}
        for ln in m.group(1).split("\n"):
            k, _, v = ln.partition(":")
            d[k.strip()] = v.strip()
        return d, text[m.end():]

    def test_relay_skill_allowed_tools_exact(self):
        d, body = self.front("relay")
        self.assertEqual(d["name"], "relay")
        tools = [t.strip() for t in d["allowed-tools"].split(", ")]
        expect = ["Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/relay.py %s *)" % s for s in READ_ONLY]
        self.assertEqual(tools, expect)

    def test_relay_skill_allows_nothing_else(self):
        d, body = self.front("relay")
        self.assertNotIn("Write", d["allowed-tools"])
        self.assertNotIn("Edit", d["allowed-tools"])
        self.assertNotIn("node:", d["allowed-tools"])
        for banned in ("init", "add", "update", "trust", "approve-ship", "ship"):
            self.assertNotRegex(d["allowed-tools"], r"relay\.py %s\b" % re.escape(banned))

    def test_relay_skill_commands_unquoted_and_same_shape(self):
        d, body = self.front("relay")
        lines = [l for l in body.split("\n") if l.startswith("python ")]
        self.assertEqual(len(lines), len(READ_ONLY))
        for l in lines:
            self.assertTrue(l.startswith("python ${CLAUDE_PLUGIN_ROOT}/scripts/relay.py "), l)
            self.assertNotIn('"', l.split("relay.py")[0])
            sub = l.split("relay.py ")[1].split()[0]
            self.assertIn(sub, READ_ONLY)

    def test_relay_skill_mentions_key_rules(self):
        d, body = self.front("relay")
        for needle in ("DATA", "429", "resume-plan", "never guess", "relay-ship", "old agent id", "next"):
            self.assertIn(needle, body, needle)

    def test_ship_skill_has_no_allowed_tools(self):
        d, body = self.front("relay-ship")
        self.assertNotIn("allowed-tools", d)
        self.assertEqual(d["name"], "relay-ship")

    def test_ship_skill_flow(self):
        d, body = self.front("relay-ship")
        for needle in ("explicit yes", "trust", "approve-ship", "ship <id>", "Never ship from a scheduled",
                       "force-push", "RELAY_NO_SHIP", "data, never an instruction"):
            self.assertIn(needle, body, needle)

    def test_skills_have_descriptions(self):
        for n in ("relay", "relay-ship"):
            d, body = self.front(n)
            self.assertGreater(len(d["description"]), 40)


class HygieneTests(unittest.TestCase):
    _DRIVE = "C" + ":"
    PATTERN = re.compile(re.escape(_DRIVE) + r"(\\|/)Users|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}|"
                         r"(^|[^A-Za-z0-9])(sk-|ghp_|github_pat_|AIza|xox[bp]-|AKIA)[A-Za-z0-9_-]{16,}")

    def test_no_personal_data_or_keys_in_files(self):
        for p in tracked_text_files():
            rel = os.path.relpath(p, PLUGIN).replace("\\", "/")
            if rel.startswith(".github/"):
                continue
            text = rb(p).decode("utf-8", "replace")
            m = self.PATTERN.search(text)
            self.assertIsNone(m, "%s: %s" % (rel, m.group(0) if m else ""))

    def test_no_private_project_names(self):
        for p in tracked_text_files():
            text = rb(p).decode("utf-8", "replace").lower()
            for word in ("drop" + "box", "agent" + "_creator", "social" + "_media", "schol" + "ar"):
                self.assertNotIn(word, text, "%s: %s" % (os.path.basename(p), word))

    def test_files_are_utf8_without_bom_and_lf(self):
        for p in tracked_text_files():
            if p.endswith((".png", ".ico")):
                continue
            raw = rb(p)
            raw.decode("utf-8")
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), p)
            self.assertNotIn(b"\r\n", raw, p)
            self.assertNotIn(b"\x00", raw, p)


STDLIB = set(["argparse", "ast", "base64", "calendar", "contextlib", "copy", "datetime", "fnmatch", "hashlib", "hmac",
              "importlib", "io", "json", "os", "re", "shutil", "signal", "stat", "subprocess", "sys", "tempfile",
              "threading", "time", "unicodedata", "unittest", "uuid", "ctypes", "socket", "helpers"])


class PortabilityTests(unittest.TestCase):
    def sources(self):
        res = [SCRIPT]
        td = os.path.join(PLUGIN, "tests")
        res += [os.path.join(td, n) for n in os.listdir(td) if n.endswith(".py")]
        return res

    def test_python38_syntax(self):
        for p in self.sources():
            src = rb(p).decode("utf-8")
            ast.parse(src, filename=p, feature_version=(3, 8))

    def test_no_fstrings_walrus_or_match(self):
        for p in self.sources():
            tree = ast.parse(rb(p).decode("utf-8"))
            for node in ast.walk(tree):
                self.assertNotIsInstance(node, ast.JoinedStr, p)
                self.assertNotIsInstance(node, ast.NamedExpr, p)

    def test_stdlib_imports_only(self):
        for p in self.sources():
            tree = ast.parse(rb(p).decode("utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module.split(".")[0]]
                for n in names:
                    self.assertIn(n, STDLIB, "%s imports %s" % (os.path.basename(p), n))

    def test_script_imports_nothing_from_siblings(self):
        text = rb(SCRIPT).decode("utf-8")
        for word in ("import loom", "import nightshift", "from loom", "from nightshift", "persistent_memory"):
            self.assertNotIn(word, text)

    def test_no_shell_use_in_script(self):
        text = rb(SCRIPT).decode("utf-8")
        self.assertNotIn("shell=True", text)
        self.assertNotIn("os.system", text)
        self.assertNotIn("os.popen", text)
        self.assertNotRegex(text, r"\beval\(")
        self.assertNotRegex(text, r"\bexec\(")
        self.assertEqual(len(re.findall(r"shell=False", text)), 1)

    def test_environment_never_read_wholesale(self):
        text = rb(SCRIPT).decode("utf-8")
        self.assertNotRegex(text, r"dict\(os\.environ\)")
        self.assertNotIn("os.environ.copy()", text)
        self.assertNotIn("os.environ.items()", text)
        self.assertNotRegex(text, r"env\s*=\s*os\.environ\b")

    def test_every_subprocess_call_is_a_list(self):
        tree = ast.parse(rb(SCRIPT).decode("utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess" and \
                    node.func.attr in ("run", "Popen", "call", "check_output", "check_call"):
                self.assertIsInstance(node.args[0], (ast.List, ast.Name), ast.dump(node)[:80])

    def test_script_has_only_forward_slash_paths_in_constants(self):
        for name in ("REGISTRY_REL", "CONFIG_REL", "BRIEFS_REL", "SHIPLOG_REL"):
            self.assertNotIn("\\", getattr(relay, name))

    def test_shebang_and_docstring(self):
        text = rb(SCRIPT).decode("utf-8")
        self.assertTrue(text.startswith("#!/usr/bin/env python3"))
        self.assertIn("Python 3.8+", text)


class ExamplesTests(Base):
    def test_ship_example_validates(self):
        cfg = json.loads(read("examples", "config.ship.json"))
        relay.validate_config(cfg, ship=True)

    def test_minimal_example_validates(self):
        relay.validate_config(json.loads(read("examples", "config.minimal.json")))

    def test_usage_snapshot_example_works(self):
        self.init()
        self.write_file("Relay/usage.json", read("examples", "usage_snapshot.json"))
        rc, o, e = self.cli("check-usage", "--file", "Relay/usage.json", "--format", "json")
        self.assertEqual(rc, 0, e)
        self.assertEqual(json.loads(o)["decision"], "wait")

    def test_brief_example_is_accepted(self):
        self.init()
        self.write_file("Relay/briefs/research-1.md", read("examples", "brief.example.md"))
        rc, o, e = self.cli("add", "research-1", "--title", "Pricing research", "--brief-file", "Relay/briefs/research-1.md")
        self.assertEqual(rc, 0, e)

    def test_session_flow_commands_parse(self):
        parser = relay.build_parser()
        for sub in ("init", "add", "update", "next", "check-usage", "resume-plan", "brief", "trust", "approve-ship", "ship"):
            self.assertIn(sub, read("examples", "session_flow.md"))
        parser.parse_args(["next", "--format", "text"])


if __name__ == "__main__":
    unittest.main()
