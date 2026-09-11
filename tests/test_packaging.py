"""Does an installed wheel still pass its own startup check?

Every other test runs from the source tree, where `vendor/` sits beside the
package and is found whether or not packaging carries it. That is exactly why
the gap survived: `pyproject.toml` said the vendored client shipped, shipped
nothing, and no test could tell the difference.

So this one leaves the source tree entirely -- build a wheel, install it into an
empty directory, and run `doctor` from there with the repository off `sys.path`.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BUILD_TIMEOUT = 300


def _run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=BUILD_TIMEOUT, **kwargs)


def _toolchain_available():
    probe = _run([sys.executable, "-c", "import setuptools, wheel, pip"])
    return probe.returncode == 0


@unittest.skipUnless(_toolchain_available(),
                     "no setuptools/wheel/pip available to build with")
class InstalledDistribution(unittest.TestCase):
    """Built once for the class: a wheel build is seconds, not milliseconds."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp.name)
        cls.wheel_dir = tmp / "dist"
        cls.site = tmp / "site"
        cls.site.mkdir()

        # Build from a clean copy, not from the repository in place. A leftover
        # `technocore_mcp.egg-info` makes setuptools reuse its old SOURCES.txt
        # and ship files the current configuration does not declare -- which is
        # exactly how the first version of this test passed against the broken
        # packaging config it was written to catch.
        cls.source = tmp / "src"
        shutil.copytree(
            REPO, cls.source,
            ignore=shutil.ignore_patterns(".git", "build", "dist", "*.egg-info",
                                          "__pycache__", "*.pyc"))
        # Recorded before building, because the build legitimately creates
        # build/ and an egg-info of its own inside this copy.
        cls.stale_before_build = sorted(
            str(p.relative_to(cls.source))
            for p in list(cls.source.glob("*.egg-info"))
            + [cls.source / "build", cls.source / "dist"]
            if p.exists())

        built = _run([sys.executable, "-m", "pip", "wheel", str(cls.source),
                      "--no-deps", "--no-build-isolation", "-w", str(cls.wheel_dir)])
        if built.returncode != 0:
            raise unittest.SkipTest(f"wheel build failed:\n{built.stdout[-1500:]}\n{built.stderr[-1500:]}")

        wheels = sorted(cls.wheel_dir.glob("technocore_mcp-*.whl"))
        if not wheels:
            raise unittest.SkipTest("no wheel produced")
        cls.wheel = wheels[0]

        installed = _run([sys.executable, "-m", "pip", "install", str(cls.wheel),
                          "--no-deps", "--target", str(cls.site)])
        if installed.returncode != 0:
            raise unittest.SkipTest(f"install failed:\n{installed.stderr[-1500:]}")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_the_wheel_carries_the_vendored_client_and_its_digest(self):
        import zipfile
        names = zipfile.ZipFile(self.wheel).namelist()
        for required in ("technocore_mcp/vendor/e2e.py",
                         "technocore_mcp/vendor/UPSTREAM.txt"):
            self.assertIn(required, names,
                          f"{required} is missing from the wheel: {sorted(names)}")

    def test_the_installed_copy_is_byte_identical_to_the_repository_copy(self):
        installed = self.site / "technocore_mcp" / "vendor" / "e2e.py"
        self.assertEqual(installed.read_bytes(), (REPO / "vendor" / "e2e.py").read_bytes())

    def test_the_build_started_from_a_source_with_no_stale_artefacts(self):
        """A leftover egg-info makes setuptools reuse its old SOURCES.txt and
        ship files the current configuration never declares. The first version
        of this test passed against the broken config for exactly that reason,
        so the cleanliness of the build input is itself worth asserting."""
        self.assertEqual(self.stale_before_build, [],
                         f"the build source carried {self.stale_before_build}")

    def test_doctor_runs_from_the_installed_wheel_with_the_repo_off_the_path(self):
        """The actual claim: startup integrity passes for an installed user.

        Run from a directory that is not the repository, with PYTHONPATH naming
        only the install target, so nothing can fall back to the source tree.
        """
        env = dict(os.environ)
        env["PYTHONPATH"] = str(self.site)
        env["TECHNOCORE_MCP_HOME"] = str(Path(self._tmp.name) / "home")
        env.pop("TECHNOCORE_MCP_HOST", None)

        result = _run([sys.executable, "-m", "technocore_mcp", "doctor"],
                      cwd=self._tmp.name, env=env)
        self.assertEqual(result.returncode, 0,
                         f"doctor failed from the installed wheel:\n"
                         f"{result.stdout}\n{result.stderr}")
        self.assertIn("startup checks passed", result.stdout)
        self.assertIn("matches UPSTREAM.txt", result.stdout)
        # Prove it really used the installed copy and not the repository's.
        self.assertNotIn(str(REPO), result.stdout)

    def test_a_tampered_installed_copy_stops_the_installed_doctor(self):
        """The check has to still be live after installation, not just present."""
        installed = self.site / "technocore_mcp" / "vendor" / "e2e.py"
        original = installed.read_bytes()
        installed.write_bytes(original + b"\n# tampered after install\n")
        try:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(self.site)
            env["TECHNOCORE_MCP_HOME"] = str(Path(self._tmp.name) / "home")
            result = _run([sys.executable, "-m", "technocore_mcp", "doctor"],
                          cwd=self._tmp.name, env=env)
            self.assertNotEqual(result.returncode, 0, "a tampered copy still started")
            self.assertIn("does not match the digest", result.stdout + result.stderr)
        finally:
            installed.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
