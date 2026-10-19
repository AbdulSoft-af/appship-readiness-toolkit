import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from appship.build_runner import run_build_and_test, content_digest, _redact_log
from appship.project_io import is_sensitive_local_file, is_machine_specific_file
from appship.analyzer import analyze_files


class BuildRunnerTests(unittest.TestCase):
    def test_digest_is_order_independent(self):
        a = {"a.txt": b"1", "b.txt": b"2"}
        b = {"b.txt": b"2", "a.txt": b"1"}
        self.assertEqual(content_digest(a), content_digest(b))
        self.assertNotEqual(content_digest(a), content_digest({"a.txt": b"x"}))

    def test_log_redaction(self):
        log = "password=very-secret api_key: abcdef0123456789\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz123456\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        redacted = _redact_log(log)
        self.assertNotIn("very-secret", redacted)
        self.assertNotIn("abcdef0123456789", redacted)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn("[REDACTED]", redacted)


    def test_local_secret_and_machine_files_are_detected(self):
        self.assertTrue(is_sensitive_local_file(".env", b"API_KEY=abc"))
        self.assertTrue(is_sensitive_local_file("app/key.properties", b"storePassword=abc"))
        self.assertTrue(is_sensitive_local_file("keys/upload.jks", b"binary"))
        self.assertFalse(is_sensitive_local_file(".env.example", b"API_KEY=put-your-key-here"))
        self.assertTrue(is_machine_specific_file("app/local.properties"))

    def test_no_build_plan_creates_honest_bundle(self):
        files = {"README.md": b"generic sample project\n"}
        report = analyze_files(files, "tiny", "test")
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "build_bundle.zip")
            result = run_build_and_test(files, "tiny", report, out, allow_dependency_install=False, timeout_seconds=60)
            self.assertFalse(result.success)
            self.assertTrue(os.path.isfile(out))
            with zipfile.ZipFile(out) as zf:
                names = set(zf.namelist())
                self.assertIn("APPSHIP_BUILD_TEST_REPORT.md", names)
                self.assertIn("APPSHIP_BUILD_LOG.txt", names)
                self.assertIn("APPSTORE_PLAYSTORE_CHECKLIST.md", names)
                contents = zf.read("APPSHIP_BUILD_TEST_REPORT.md").decode()
                self.assertIn("No installable/release artifact was produced", contents)


if __name__ == "__main__":
    unittest.main()
