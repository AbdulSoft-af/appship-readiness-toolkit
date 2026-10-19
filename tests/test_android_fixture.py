import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "examples" / "sample_android_project"


class AndroidFixtureTests(unittest.TestCase):
    def test_real_build_files_are_present(self):
        for relative in (
            "settings.gradle", "build.gradle", "gradle.properties", "app/build.gradle",
            "gradlew", "gradlew.bat", "gradlew.ps1", "gradle/wrapper/gradle-wrapper.properties",
            "app/src/main/AndroidManifest.xml",
            "app/src/main/java/com/appship/demo/MainActivity.java",
            "app/src/test/java/com/appship/demo/AppMessageTest.java",
        ):
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file(), relative)

    def test_sample_is_target_api_36_with_exported_launcher(self):
        gradle = (ROOT / "app/build.gradle").read_text(encoding="utf-8")
        manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
        self.assertIn("compileSdk 36", gradle)
        self.assertIn("targetSdk 36", gradle)
        self.assertIn('android:exported="true"', manifest)
        self.assertNotIn("exit 1", (ROOT / "gradlew").read_text(encoding="utf-8"))
        shell_script = (ROOT / "gradlew").read_text(encoding="utf-8")
        powershell_script = (ROOT / "gradlew.ps1").read_text(encoding="utf-8")
        wrapper_properties = (ROOT / "gradle/wrapper/gradle-wrapper.properties").read_text(encoding="utf-8")
        for content in (shell_script, powershell_script, wrapper_properties):
            self.assertIn("8.14.6", content)
            self.assertIn("7988ed071b2a07900e2ec715fca15c6ab72bce6db433af301fa7fa7e9407bd24", content)
        self.assertIn("ExpectedSha256", powershell_script)
        java_message = (ROOT / "app/src/main/java/com/appship/demo/AppMessage.java").read_text(encoding="utf-8")
        self.assertIn(r"AppShip Demo\nAndroid", java_message)
        self.assertNotIn('return "AppShip Demo\nAndroid', java_message.replace(r"\n", ""))


if __name__ == "__main__":
    unittest.main()
