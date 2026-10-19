import plistlib
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from appship.artifact_verifier import verify_artifact


class ArtifactVerifierTests(unittest.TestCase):
    def _ipa(self, path: Path):
        info = {
            "CFBundleIdentifier": "com.appship.demo",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
        }
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(info))
            archive.writestr("Payload/Demo.app/_CodeSignature/CodeResources", b"test-signature-resources")
            archive.writestr("Payload/Demo.app/Demo", b"fake-binary")

    def test_ipa_reports_metadata_and_reviews_signature_off_macos(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.ipa"
            self._ipa(path)
            with patch("appship.artifact_verifier.platform.system", return_value="Linux"):
                report = verify_artifact(str(path))
            self.assertEqual(report.metadata["bundle_identifier"], "com.appship.demo")
            checks = {item.check_id: item for item in report.checks}
            self.assertEqual(checks["IPA-SIG"].status, "REVIEW")

    def test_ipa_runs_codesign_on_macos_when_available(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.ipa"
            self._ipa(path)
            with patch("appship.artifact_verifier.platform.system", return_value="Darwin"), \
                 patch("appship.artifact_verifier.shutil.which", return_value="/usr/bin/codesign"), \
                 patch("appship.artifact_verifier._run_verifier", return_value=(0, "valid on disk")) as verify:
                report = verify_artifact(str(path))
            checks = {item.check_id: item for item in report.checks}
            self.assertEqual(checks["IPA-SIG"].status, "PASS")
            self.assertIn("codesign", verify.call_args.args[0][0])


    def test_ipa_codesign_reconstruction_preserves_executable_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.ipa"
            info = {"CFBundleIdentifier": "com.appship.demo", "CFBundleShortVersionString": "1.0.0", "CFBundleVersion": "1"}
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, content, mode in (
                    ("Payload/Demo.app/Info.plist", plistlib.dumps(info), 0o644),
                    ("Payload/Demo.app/_CodeSignature/CodeResources", b"test-signature-resources", 0o644),
                    ("Payload/Demo.app/Demo", b"fake-binary", 0o755),
                ):
                    item = zipfile.ZipInfo(name)
                    item.create_system = 3
                    item.external_attr = (stat.S_IFREG | mode) << 16
                    archive.writestr(item, content)

            def verify_command(command, timeout=120):
                binary = Path(command[-1]) / "Demo"
                self.assertTrue(binary.is_file())
                self.assertTrue(binary.stat().st_mode & stat.S_IXUSR, "Executable bit must survive temporary reconstruction")
                return 0, "valid on disk"

            with patch("appship.artifact_verifier.platform.system", return_value="Darwin"), \
                 patch("appship.artifact_verifier.shutil.which", return_value="/usr/bin/codesign"), \
                 patch("appship.artifact_verifier._run_verifier", side_effect=verify_command):
                report = verify_artifact(str(path))
            checks = {item.check_id: item for item in report.checks}
            self.assertEqual(checks["IPA-SIG"].status, "PASS")

    def test_ipa_reports_a_failed_codesign_on_macos(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.ipa"
            self._ipa(path)
            with patch("appship.artifact_verifier.platform.system", return_value="Darwin"), \
                 patch("appship.artifact_verifier.shutil.which", return_value="/usr/bin/codesign"), \
                 patch("appship.artifact_verifier._run_verifier", return_value=(1, "code object is not signed")):
                report = verify_artifact(str(path))
            checks = {item.check_id: item for item in report.checks}
            self.assertEqual(checks["IPA-SIG"].status, "FAIL")


if __name__ == "__main__":
    unittest.main()
