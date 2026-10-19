import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appship import user_settings


class UserSettingsTests(unittest.TestCase):
    def test_defaults_and_save_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "settings.json"
            with patch.object(user_settings, "settings_path", return_value=target):
                defaults = user_settings.load_settings()
                self.assertEqual(defaults["ollama_url"], "http://127.0.0.1:11434")
                user_settings.save_settings({
                    "ollama_url": "http://localhost:11434/",
                    "ollama_model": "qwen2.5-coder:7b",
                    "ai_timeout_seconds": 9999,
                })
                saved = user_settings.load_settings()
                self.assertEqual(saved["ollama_url"], "http://localhost:11434/")
                self.assertEqual(saved["ollama_model"], "qwen2.5-coder:7b")
                self.assertEqual(saved["ai_timeout_seconds"], 600)

    def test_invalid_config_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "settings.json"
            target.write_text("not json", encoding="utf-8")
            with patch.object(user_settings, "settings_path", return_value=target):
                self.assertEqual(user_settings.load_settings()["ollama_model"], "qwen2.5-coder:7b")


if __name__ == "__main__":
    unittest.main()
