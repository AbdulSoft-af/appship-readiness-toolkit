"""Small per-user AppShip settings store using only the Python standard library."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_SETTINGS = {
    "ollama_url": "http://127.0.0.1:11434",
    "ollama_model": "qwen2.5-coder:7b",
    "ai_timeout_seconds": 180,
}


def settings_path() -> Path:
    if os.name == "nt":
        root = os.environ.get("APPDATA")
        base = Path(root) if root else Path.home() / "AppData" / "Roaming"
        return base / "AppShip" / "settings.json"
    if os.sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "AppShip" / "settings.json"
    root = os.environ.get("XDG_CONFIG_HOME")
    base = Path(root) if root else Path.home() / ".config"
    return base / "appship" / "settings.json"


def load_settings() -> dict[str, Any]:
    values = dict(DEFAULT_SETTINGS)
    try:
        path = settings_path()
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for key in DEFAULT_SETTINGS:
                if key in data and isinstance(data[key], type(DEFAULT_SETTINGS[key])):
                    values[key] = data[key]
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    values["ollama_url"] = str(values["ollama_url"]).strip() or DEFAULT_SETTINGS["ollama_url"]
    values["ollama_model"] = str(values["ollama_model"]).strip() or DEFAULT_SETTINGS["ollama_model"]
    try:
        values["ai_timeout_seconds"] = max(10, min(int(values["ai_timeout_seconds"]), 600))
    except (ValueError, TypeError):
        values["ai_timeout_seconds"] = DEFAULT_SETTINGS["ai_timeout_seconds"]
    return values


def save_settings(settings: dict[str, Any]) -> Path:
    payload = dict(DEFAULT_SETTINGS)
    payload["ollama_url"] = str(settings.get("ollama_url", DEFAULT_SETTINGS["ollama_url"])).strip()
    payload["ollama_model"] = str(settings.get("ollama_model", DEFAULT_SETTINGS["ollama_model"])).strip()
    try:
        payload["ai_timeout_seconds"] = max(10, min(int(settings.get("ai_timeout_seconds", 180)), 600))
    except (ValueError, TypeError):
        payload["ai_timeout_seconds"] = 180
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)
    return path
