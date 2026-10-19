import contextlib
import io
import json
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from appship.cli import main, doctor_report
from appship.artifact_verifier import verify_artifact
from appship.analyzer import analyze_files
from appship.html_report import render_html_report
from appship.policy import get_android_profile, policy_snapshot


ANDROID_FILES = {
    "README.md": b"Sample mobile app\n",
    "app/build.gradle": b"android { namespace 'com.acme.demo'; compileSdk 36; defaultConfig { applicationId 'com.acme.demo'; minSdk 23; targetSdk 35; versionCode 1; versionName '1.0' } }\n",
    "app/src/main/AndroidManifest.xml": b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.demo"><application><activity android:name=".MainActivity"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity></application></manifest>''',
    "gradlew": b"#!/bin/sh\nexit 1\n",
}


class PolicyAndHtmlTests(unittest.TestCase):
    def test_category_profiles_have_current_thresholds(self):
        self.assertEqual(get_android_profile("standard").required_target_api, 36)
        self.assertEqual(get_android_profile("wear-os").required_target_api, 35)
        self.assertEqual(get_android_profile("automotive").required_target_api, 35)
        self.assertEqual(get_android_profile("android-tv").required_target_api, 34)
        self.assertEqual(get_android_profile("android-xr").required_target_api, 34)
        with self.assertRaises(ValueError):
            get_android_profile("unknown-device")

    def test_profile_changes_target_sdk_finding(self):
        standard = analyze_files(ANDROID_FILES, "sample", "test", "standard")
        wear = analyze_files(ANDROID_FILES, "sample", "test", "wear-os")
        standard_ids = {f.id for f in standard.findings}
        wear_ids = {f.id for f in wear.findings}
        self.assertIn("AND-002", standard_ids)
        self.assertIn("AND-003", wear_ids)
        self.assertEqual(wear.android_app_category, "wear-os")

    def test_html_report_escapes_untrusted_content_and_contains_brand(self):
        report = analyze_files({"README.md": b"safe"}, "<script>alert(1)</script>", "test")
        html = render_html_report(report)
        self.assertIn("APPSHIP", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("not an official", html.lower())

    def test_policy_snapshot_is_dated_and_links_official_sources(self):
        snapshot = policy_snapshot()
        self.assertEqual(snapshot["checked_on"], "2026-10-19")
        self.assertIn("google_target_api", snapshot["official_sources"])
        self.assertTrue(snapshot["official_sources"]["google_target_api"].startswith("https://"))


class ArtifactVerifierTests(unittest.TestCase):
    def test_apk_structure_is_inspected_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "sample.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"binary manifest placeholder")
                archive.writestr("classes.dex", b"dex placeholder")
            report = verify_artifact(str(apk))
            ids = {check.check_id for check in report.checks}
            self.assertIn("ZIP-000", ids)
            self.assertIn("APK-001", ids)
            self.assertIn("APK-002", ids)
            self.assertIn("APK-SIG", ids)
            self.assertIn(report.overall_status, {"PASS", "FAIL", "REVIEW"})

    def test_artifact_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "unsafe.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("../outside.txt", b"not safe")
            report = verify_artifact(str(apk))
            self.assertEqual(report.overall_status, "FAIL")
            self.assertIn("ZIP-003", {check.check_id for check in report.checks})

    def test_ipa_metadata_is_read_and_signature_remains_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            ipa = Path(tmp) / "sample.ipa"
            info = plistlib.dumps({"CFBundleIdentifier": "com.example.sample", "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1"})
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Sample.app/Info.plist", info)
                archive.writestr("Payload/Sample.app/_CodeSignature/CodeResources", b"signature marker")
                archive.writestr("Payload/Sample.app/embedded.mobileprovision", b"profile marker")
            report = verify_artifact(str(ipa))
            self.assertEqual(report.metadata["bundle_identifier"], "com.example.sample")
            self.assertIn("IPA-SIG", {check.check_id for check in report.checks})
            self.assertEqual(report.overall_status, "REVIEW")


class CliTests(unittest.TestCase):
    def test_scan_exports_json_html_checklist_inventory_and_prepared_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            root.mkdir()
            for name, value in ANDROID_FILES.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(value)
            report_path = Path(tmp) / "report.json"
            checklist_path = Path(tmp) / "checklist.md"
            inventory_path = Path(tmp) / "inventory.json"
            prepared_path = Path(tmp) / "prepared.zip"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([
                    "scan", str(root), "--android-profile", "wear-os", "--format", "json",
                    "--output", str(report_path), "--checklist", str(checklist_path),
                    "--inventory", str(inventory_path), "--prepared-zip", str(prepared_path),
                ])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(report_path.read_text())['android_app_category'], 'wear-os')
            self.assertIn("API 35", checklist_path.read_text())
            self.assertIn("content_digest_sha256", json.loads(inventory_path.read_text()))
            with zipfile.ZipFile(prepared_path) as zf:
                names = set(zf.namelist())
                self.assertTrue(any(x.endswith("APPSHIP_READINESS_REPORT.html") for x in names))
                self.assertTrue(any(x.endswith("APPSHIP_SOURCE_INVENTORY.json") for x in names))

    def test_cli_artifact_report_html_and_require_signature_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.ipa"
            output = Path(tmp) / "artifact-report.html"
            info = plistlib.dumps({"CFBundleIdentifier": "com.example.sample", "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1"})
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("Payload/Sample.app/Info.plist", info)
                archive.writestr("Payload/Sample.app/_CodeSignature/CodeResources", b"marker")
                archive.writestr("Payload/Sample.app/embedded.mobileprovision", b"marker")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["verify-artifact", str(artifact), "--format", "html", "--output", str(output), "--require-signature"])
            self.assertEqual(code, 1)
            html = output.read_text(encoding="utf-8")
            self.assertIn("Artifact verification", html)
            self.assertIn("REVIEW", html)

    def test_cli_refuses_to_overwrite_input_zip_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("README.md", "safe sample")
            before = source.read_bytes()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["scan", str(source), "--output", str(source), "--format", "json"])
            self.assertEqual(code, 2)
            self.assertEqual(source.read_bytes(), before)
            self.assertIn("matches the input source", stderr.getvalue())

    def test_prepared_zip_is_blocked_when_possible_secret_remains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            root.mkdir()
            (root / "README.md").write_text("mobile project", encoding="utf-8")
            (root / "config.js").write_text("const API_KEY = 'real_secret_value_123456';", encoding="utf-8")
            out = Path(tmp) / "prepared.zip"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["scan", str(root), "--prepared-zip", str(out)])
            self.assertEqual(code, 2)
            self.assertFalse(out.exists())
            self.assertIn("possible hard-coded secret remains", stderr.getvalue())

    def test_cli_refuses_duplicate_output_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            root.mkdir()
            (root / "README.md").write_text("sample", encoding="utf-8")
            output_path = Path(tmp) / "same.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["scan", str(root), "--format", "json", "--output", str(output_path), "--inventory", str(output_path)])
            self.assertEqual(code, 2)
            self.assertFalse(output_path.exists())
            self.assertIn("conflicts with", stderr.getvalue())

    def test_cli_build_test_failure_returns_nonzero_even_without_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            root.mkdir()
            (root / "README.md").write_text("not a supported mobile project", encoding="utf-8")
            bundle = Path(tmp) / "build.zip"
            output = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr):
                code = main(["scan", str(root), "--build-test", "--confirm-execute-build-scripts", "--build-bundle", str(bundle)])
            self.assertEqual(code, 1)
            self.assertTrue(bundle.exists())
            self.assertIn("BUILD/TEST FAILED", stderr.getvalue())

    def test_strict_mode_fails_on_high_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            root.mkdir()
            (root / "README.md").write_text("not a mobile project", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["scan", str(root), "--strict"])
            self.assertEqual(code, 1)

    def test_doctor_is_json_serializable(self):
        report = doctor_report()
        self.assertIn("toolchains", report)
        json.dumps(report)


if __name__ == "__main__":
    unittest.main()
