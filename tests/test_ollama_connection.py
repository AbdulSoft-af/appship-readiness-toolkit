import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from appship.ai_assist import ollama_check_connection, ollama_list_models


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/version":
            payload = {"version": "0.5.7"}
        elif self.path == "/api/tags":
            payload = {"models": [{"name": "qwen2.5-coder:7b"}, {"name": "llama3.2:latest"}]}
        else:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class OllamaConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_connection_version(self):
        result = ollama_check_connection(self.base_url)
        self.assertTrue(result["connected"])
        self.assertEqual(result["version"], "0.5.7")

    def test_list_installed_models(self):
        self.assertEqual(ollama_list_models(self.base_url), ["llama3.2:latest", "qwen2.5-coder:7b"])


if __name__ == "__main__":
    unittest.main()
