import unittest
from appship.ai_assist import apply_unified_diff, extract_unified_diff, _validate_local_url, make_repair_prompt


class AIAssistTests(unittest.TestCase):
    def setUp(self):
        self.files = {
            "app/src/MainActivity.kt": b"package demo\nfun main() {\n    println(\"old\")\n}\n",
            "README.md": b"hello\n",
            ".env": b"API_KEY=do-not-send\n",
            "app/build.gradle": b"android {\n  compileSdk 36\n  // storePassword = 'real-super-secret-value'\n}\n",
        }

    def test_apply_valid_patch_to_copy(self):
        patch = """--- a/app/src/MainActivity.kt
+++ b/app/src/MainActivity.kt
@@ -3,1 +3,1 @@
-    println(\"old\")
+    println(\"new\")
"""
        updated, changes = apply_unified_diff(self.files, patch)
        self.assertIn(b'println("new")', updated["app/src/MainActivity.kt"])
        self.assertIn(b'println("old")', self.files["app/src/MainActivity.kt"])
        self.assertEqual(len(changes), 1)

    def test_patch_refuses_unknown_path_and_traversal(self):
        patch = """--- a/../../evil.kt
+++ b/../../evil.kt
@@ -1,1 +1,1 @@
-old
+new
"""
        with self.assertRaises(ValueError):
            apply_unified_diff(self.files, patch)

    def test_patch_refuses_context_mismatch(self):
        patch = """--- a/README.md
+++ b/README.md
@@ -1,1 +1,1 @@
-not-the-source
+replacement
"""
        with self.assertRaises(ValueError):
            apply_unified_diff(self.files, patch)

    def test_patch_refuses_creation_deletion_and_secrets(self):
        new_file = """--- /dev/null
+++ b/new.kt
@@ -0,0 +1,1 @@
+fun main() {}
"""
        with self.assertRaises(ValueError):
            apply_unified_diff(self.files, new_file)
        secret_patch = """--- a/.env
+++ b/.env
@@ -1,1 +1,1 @@
-API_KEY=do-not-send
+API_KEY=redacted
"""
        with self.assertRaises(ValueError):
            apply_unified_diff(self.files, secret_patch)

    def test_extract_diff_from_markdown(self):
        response = "Suggested fix.\n```diff\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-hello\n+hello world\n```"
        self.assertTrue(extract_unified_diff(response).startswith("--- a/README.md"))

    def test_only_loopback_ollama_endpoint_is_allowed(self):
        self.assertEqual(_validate_local_url("http://127.0.0.1:11434/"), "http://127.0.0.1:11434")
        with self.assertRaises(ValueError):
            _validate_local_url("https://api.example.com")
        with self.assertRaises(ValueError):
            _validate_local_url("http://example.com:11434")
        with self.assertRaises(ValueError):
            _validate_local_url("http://127.0.0.1:11434/proxy")
        with self.assertRaises(ValueError):
            _validate_local_url("http://user:password@127.0.0.1:11434")

    def test_secret_file_not_added_to_ai_context(self):
        prompt = make_repair_prompt("failed", self.files)
        self.assertNotIn("do-not-send", prompt)
        self.assertNotIn("real-super-secret-value", prompt)
        self.assertNotIn("--- FILE: app/build.gradle ---", prompt)
        self.assertIn("MainActivity.kt", prompt)
        self.assertIn("untrusted data", prompt)


    def test_local_signing_and_provider_secret_files_are_omitted(self):
        sensitive_files = {
            "android/key.properties": b"storePassword=shortpass\nkeyPassword=shortpass\n",
            "ios/AuthKey_ABCD123456.p8": b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
            "app/Main.kt": b"fun main() {}\n",
        }
        prompt = make_repair_prompt("build failed", sensitive_files)
        self.assertNotIn("shortpass", prompt)
        self.assertNotIn("fake", prompt)
        self.assertIn("Main.kt", prompt)

    def test_patch_refuses_files_omitted_from_ai_context(self):
        patch = """--- a/app/build.gradle
+++ b/app/build.gradle
@@ -2,1 +2,1 @@
-  compileSdk 36
+  compileSdk 35
"""
        with self.assertRaises(ValueError):
            apply_unified_diff(self.files, patch)

    def test_patch_refuses_signing_changes(self):
        patch = """--- a/app/src/MainActivity.kt
+++ b/app/src/MainActivity.kt
@@ -3,1 +3,1 @@
-    println(\"old\")
+    signingConfig = signingConfigs.getByName(\"release\")
+    println(\"new\")
"""
        with self.assertRaises(ValueError):
            apply_unified_diff(self.files, patch)

    def test_patch_supports_multiple_hunks(self):
        patch = """--- a/app/src/MainActivity.kt
+++ b/app/src/MainActivity.kt
@@ -1,1 +1,1 @@
-package demo
+package example
@@ -4,1 +4,1 @@
-}
+    println(\"done\")
"""
        # The second hunk's context must still match the file after the first hunk.
        updated, _ = apply_unified_diff(self.files, patch)
        self.assertIn(b"package example", updated["app/src/MainActivity.kt"])
        self.assertIn(b'println("done")', updated["app/src/MainActivity.kt"])


if __name__ == "__main__":
    unittest.main()
