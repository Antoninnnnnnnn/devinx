"""sidecar/build.py: the patched claude-code-proxy behind the gpt-* route.

Hermetic: git, cargo and systemctl are never run; the checks are on what the
script decides and writes.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("sidecar_build",
                                              ROOT / "sidecar" / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def quiet():
    return contextlib.redirect_stdout(io.StringIO())


class PackagedFilesTests(unittest.TestCase):

    def test_the_patch_and_the_unit_ship_with_the_repo(self):
        patch = Path(build.PATCH).read_text()
        self.assertIn("reject_browser_requests", patch)
        self.assertIn(build.PATCH_MARKER.decode(), patch)
        self.assertTrue(patch.startswith("diff --git a/src/server.rs"))

    def test_the_unit_names_no_machine_and_renders_its_placeholders(self):
        template = Path(build.UNIT_TEMPLATE).read_text()
        self.assertNotIn("/home/", template)
        unit = build.render_unit("/opt/x/claude-code-proxy", 19999)
        self.assertIn("ExecStart=/opt/x/claude-code-proxy serve --no-monitor "
                      "--port 19999", unit)
        self.assertIn("CCP_BIND_ADDRESS=127.0.0.1", unit)
        self.assertIn("CCP_CODEX_SERVER_COMPACTION=1", unit)
        self.assertNotIn("@", unit)

    def test_a_binary_under_home_is_written_with_systemds_h(self):
        home = os.path.expanduser("~")
        unit = build.render_unit(os.path.join(home, ".local", "bin",
                                              "claude-code-proxy"), 18765)
        self.assertIn("ExecStart=%h/.local/bin/claude-code-proxy serve", unit)
        self.assertNotIn(home, unit)

    def test_the_default_port_is_the_one_devinx_expects(self):
        import devinx
        self.assertTrue(devinx.GPT_UPSTREAM.endswith(f":{build.DEFAULT_PORT}")
                        or "DEVINX_GPT_UPSTREAM" in os.environ)

    def test_the_readme_no_longer_points_outside_the_repo(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("devinx-local", readme)
        self.assertIn("sidecar/build.py", readme)


class CheckoutTests(unittest.TestCase):

    def test_a_moved_tag_is_refused(self):
        def fake(cmd, cwd=None, capture=False):
            return "0" * 40 + "\n" if cmd[1:3] == ["rev-parse", "HEAD"] else ""
        with tempfile.TemporaryDirectory() as src, \
                mock.patch.object(build, "run", side_effect=fake):
            os.makedirs(os.path.join(src, ".git"))
            with self.assertRaises(build.BuildError) as ctx:
                build.checkout(src)
        self.assertIn("tag moved", str(ctx.exception))

    def test_a_reused_checkout_is_reset_before_it_is_patched(self):
        calls = []

        def fake(cmd, cwd=None, capture=False):
            calls.append(cmd)
            return build.COMMIT + "\n" if cmd[1:3] == ["rev-parse", "HEAD"] else ""
        with tempfile.TemporaryDirectory() as src, \
                mock.patch.object(build, "run", side_effect=fake):
            os.makedirs(os.path.join(src, ".git"))
            build.checkout(src)
        verbs = [c[1] for c in calls]
        self.assertEqual(verbs, ["fetch", "checkout", "clean", "rev-parse",
                                 "apply", "apply"])
        self.assertIn(build.COMMIT, calls[1])
        self.assertIn("target", calls[2])          # the build cache is kept
        self.assertIn("--check", calls[4])

    def test_cargo_missing_says_how_to_get_it(self):
        with tempfile.TemporaryDirectory() as home, \
                mock.patch.object(build.shutil, "which", return_value=None), \
                mock.patch.object(build.os.path, "expanduser", return_value=home):
            with self.assertRaises(build.BuildError) as ctx:
                build.find_cargo()
        self.assertIn("rustup", str(ctx.exception))


class InstallBinaryTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.exe = os.path.join(self.dir.name, "built")
        Path(self.exe).write_bytes(b"ELF " + build.PATCH_MARKER + b" v2")
        self.dest = os.path.join(self.dir.name, "bin", "claude-code-proxy")

    def test_an_unpatched_binary_is_kept_beside_it(self):
        os.makedirs(os.path.dirname(self.dest))
        Path(self.dest).write_bytes(b"ELF upstream")
        with quiet():
            self.assertTrue(build.install_binary(self.exe, self.dest))
        self.assertEqual(Path(self.dest + ".unpatched").read_bytes(), b"ELF upstream")
        self.assertEqual(Path(self.dest).read_bytes(), Path(self.exe).read_bytes())
        self.assertTrue(os.access(self.dest, os.X_OK))

    def test_an_older_patched_build_is_replaced_without_a_backup(self):
        os.makedirs(os.path.dirname(self.dest))
        Path(self.dest).write_bytes(b"ELF " + build.PATCH_MARKER + b" v1")
        with quiet():
            self.assertTrue(build.install_binary(self.exe, self.dest))
        self.assertFalse(os.path.exists(self.dest + ".unpatched"))

    def test_the_same_build_changes_nothing(self):
        with quiet():
            build.install_binary(self.exe, self.dest)
            self.assertFalse(build.install_binary(self.exe, self.dest))

    def test_no_temporary_file_is_left_behind(self):
        with quiet():
            build.install_binary(self.exe, self.dest)
        self.assertEqual(os.listdir(os.path.dirname(self.dest)),
                         ["claude-code-proxy"])


class ServiceTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.dir.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.calls = []
        patcher = mock.patch.object(build, "systemctl",
                                    side_effect=lambda *a, **k: self.calls.append(a))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.unit = os.path.join(self.dir.name, "systemd", "user", build.UNIT_NAME)

    def install(self, active, **kw):
        args = dict(dest="/x/claude-code-proxy", port=18765, force=False,
                    restart=False, binary_changed=False)
        args.update(kw)
        out = io.StringIO()
        with mock.patch.object(build, "service_active", return_value=active), \
                contextlib.redirect_stdout(out):
            build.install_service(**args)
        return out.getvalue()

    def test_a_fresh_install_writes_enables_and_starts(self):
        self.install(active=False)
        self.assertIn("ExecStart=/x/claude-code-proxy", Path(self.unit).read_text())
        self.assertEqual(self.calls, [("daemon-reload",),
                                      ("enable", "--quiet", build.UNIT_NAME),
                                      ("start", build.UNIT_NAME)])

    def test_a_running_sidecar_is_not_restarted_unless_asked(self):
        out = self.install(active=True, binary_changed=True)
        self.assertNotIn(("restart", build.UNIT_NAME), self.calls)
        self.assertIn("systemctl --user restart", out)
        self.calls.clear()
        self.install(active=True, binary_changed=True, restart=True)
        self.assertIn(("restart", build.UNIT_NAME), self.calls)

    def test_an_unchanged_running_sidecar_is_left_alone(self):
        self.install(active=False)
        self.calls.clear()
        self.install(active=True)
        self.assertEqual(self.calls, [("enable", "--quiet", build.UNIT_NAME)])

    def test_a_unit_edited_by_hand_is_kept_unless_forced(self):
        os.makedirs(os.path.dirname(self.unit))
        Path(self.unit).write_text("[Service]\nExecStart=/mine\n")
        out = self.install(active=True)
        self.assertEqual(Path(self.unit).read_text(), "[Service]\nExecStart=/mine\n")
        self.assertIn("--force", out)
        self.install(active=True, force=True)
        self.assertIn("ExecStart=/x/claude-code-proxy", Path(self.unit).read_text())


class InstallerTests(unittest.TestCase):

    def test_install_gpt_runs_the_build_and_survives_its_failure(self):
        import install
        seen = []

        class Fake:
            @staticmethod
            def main(argv):
                seen.append(argv)
                return 1
        loader = mock.Mock()
        loader.exec_module = lambda module: setattr(module, "main", Fake.main)
        spec = mock.Mock(loader=loader)
        with mock.patch("importlib.util.spec_from_file_location", return_value=spec), \
                mock.patch("importlib.util.module_from_spec",
                           return_value=type("M", (), {})()), \
                quiet():
            install.install_gpt_sidecar(force=True)
        self.assertEqual(seen, [["--force"]])


if __name__ == "__main__":
    unittest.main()
