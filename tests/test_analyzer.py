import unittest
import tempfile
import os
import zipfile
import plistlib
from appship.analyzer import analyze_files
from appship.project_io import apply_safe_fixes, safe_member_name, load_zip, create_zip_from_files
from appship.reports import to_markdown

class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.files = {
            "app/src/main/AndroidManifest.xml": b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
              <uses-permission android:name="android.permission.CAMERA" />
              <application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true">
                <activity android:name=".MainActivity">
                  <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
                </activity>
              </application>
            </manifest>''',
            "app/build.gradle": b'''android { namespace "com.example.demo"; compileSdk 35; defaultConfig { applicationId "com.example.demo"; minSdk 23; targetSdk 35; versionCode 1; versionName "1.0" } }''',
            "gradlew": b"#!/bin/sh\n",
            "app/src/main/java/MainActivity.kt": b"package com.example\n",
        }

    def test_detects_android_policy_security_and_launcher_exported(self):
        report = analyze_files(self.files, "sample", "test")
        ids = {f.id for f in report.findings}
        self.assertIn("AND-002", ids)
        self.assertIn("AND-007", ids)
        self.assertIn("AND-008", ids)
        self.assertIn("AND-010", ids)
        launcher = next(f for f in report.findings if f.id == "AND-010")
        self.assertTrue(launcher.auto_fixable)
        self.assertTrue(report.files_scanned >= 4)

    def test_safe_fix_updates_launcher_and_gitignore(self):
        patched, changes = apply_safe_fixes(self.files)
        manifest = patched["app/src/main/AndroidManifest.xml"].decode()
        self.assertIn('android:exported="true"', manifest)
        self.assertIn(".gitignore", patched)
        ignore_text = patched[".gitignore"].decode("utf-8")
        self.assertIn(".env.*", ignore_text)
        self.assertIn("*.p12", ignore_text)
        self.assertTrue(any("android:exported" in c for c in changes))

    def test_path_traversal_filter(self):
        self.assertTrue(safe_member_name("app/src/main/AndroidManifest.xml"))
        self.assertFalse(safe_member_name("../../evil.txt"))
        self.assertFalse(safe_member_name("C:/Windows/file.txt"))


    def test_ios_info_plist_checks(self):
        plist = plistlib.dumps({"CFBundleIdentifier": "com.example.iosdemo", "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}})
        report = analyze_files({"ios/Runner/Info.plist": plist, "ios/Runner.xcodeproj/project.pbxproj": b"// xcode project"}, "ios-demo", "test")
        ids = {f.id for f in report.findings}
        self.assertIn("IOS-002", ids)
        self.assertIn("IOS-003", ids)
        self.assertIn("IOS-004", ids)

    def test_zip_round_trip_and_markdown_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            zpath = os.path.join(tmp, "sample.zip")
            create_zip_from_files(self.files, zpath)
            files, notes = load_zip(zpath)
            self.assertIn("app/src/main/AndroidManifest.xml", files)
            report = analyze_files(files, "sample", "test")
            markdown = to_markdown(report, notes)
            self.assertIn("Readiness Report", markdown)
            self.assertIn("AND-002", markdown)


    def test_recognizes_common_provider_tokens(self):
        token_files = {
            "app/settings.js": b"const apiToken = 'ghp_" + b"a" * 36 + b"';",
            "app/config.txt": b"Authorization: Bearer " + b"abcdEFgh0123456789ABCDEFGHijklmnop" + b"\n",
        }
        report = analyze_files(token_files, "token-demo", "test")
        secret_paths = {f.path for f in report.findings if f.id == "SEC-001"}
        self.assertIn("app/settings.js", secret_paths)
        self.assertIn("app/config.txt", secret_paths)

    def test_dot_env_path_is_preserved_and_possible_secret_detected(self):
        report = analyze_files({".env": b"API_KEY=abcdefghijklmnopqrstuvwxyz123456\n"}, "secrets", "test")
        findings = [f for f in report.findings if f.id == "SEC-001"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, ".env")

    def test_detects_floating_gradle_dependency_version(self):
        files = {
            "README.md": b"sample",
            "app/build.gradle": b"""plugins { id 'com.android.application' }
android { compileSdk 36 }
dependencies { implementation 'com.example:library:+' }
""",
            "app/src/main/AndroidManifest.xml": b"<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"><application/></manifest>",
        }
        report = analyze_files(files, "floating", "test")
        self.assertIn("GEN-007", {finding.id for finding in report.findings})

    def test_unknown_project_warns(self):
        report = analyze_files({"hello.txt": b"hello"}, "tiny", "test")
        ids = {f.id for f in report.findings}
        self.assertIn("GEN-006", ids)
        self.assertIn("GEN-005", ids)

if __name__ == "__main__":
    unittest.main()
