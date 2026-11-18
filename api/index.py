from email.parser import BytesParser
from email.policy import default as email_default
from http.server import BaseHTTPRequestHandler
import json
import os
import sys
import time
from urllib.parse import parse_qs, urlparse

# Ensure repository root is importable inside Vercel Python serverless functions
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core import (
    PUBLIC_DIR,
    cache_stats,
    check_cache_sync,
    check_eboard_sync,
    check_ebr_sync,
    check_eduboard_sync,
    parse_pdf_for_roll_sync,
    read_profiles,
    verify_token_payload,
    write_profiles,
)
from eboard_client import eboard_client
from eduboard_client import eduboard_client


def _parse_multipart(content_type, body_bytes):
    """Parse multipart/form-data cleanly using stdlib email parser (Python 3.10-3.14 safe)."""
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin-1")
    msg = BytesParser(policy=email_default).parsebytes(header + body_bytes)
    fields = {}
    if msg.is_multipart():
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if name:
                fields[name] = part.get_payload(decode=True) or b""
    return fields


class handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_text(self, body, content_type="text/plain; charset=utf-8", status=200):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _origin(self):
        proto = self.headers.get("X-Forwarded-Proto", "https")
        host = self.headers.get("Host", "localhost")
        return f"{proto}://{host}"

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        try:
            if path == "/health":
                return self._send_json({"status": "ok", "service": "ResultSniper BD", "runtime": "vercel", "timestamp": int(time.time()), "cache": cache_stats()})

            if path == "/api/verify":
                token = (qs.get("t") or [""])[0]
                return self._send_json(verify_token_payload(token))

            if path == "/api/eduboard/captcha":
                return self._send_json(eduboard_client.get_captcha())

            if path == "/api/eboard/captcha":
                sid, uri = eboard_client.create_captcha_session()
                return self._send_json({"success": True, "session_id": sid, "captcha_img": uri})

            if path == "/api/profiles":
                return self._send_json({"success": True, "profiles": read_profiles()})

            if path == "/api/sniper/status":
                return self._send_json({"status": "CLIENT_MODE", "attempts": 0, "logs": []})

            if path in ("/robots.txt", "/sitemap.xml"):
                fpath = os.path.join(PUBLIC_DIR, path.lstrip("/"))
                with open(fpath, "r", encoding="utf-8") as f:
                    content = (
                        f.read()
                        .replace("https://resultsniper-bd.vercel.app", self._origin())
                        .replace("https://resultsniper-bd.local", self._origin())
                    )
                ctype = "application/xml; charset=utf-8" if path.endswith(".xml") else "text/plain; charset=utf-8"
                return self._send_text(content, content_type=ctype)

            return self._send_json({"success": False, "error": f"Endpoint not found: {path}"}, status=404)
        except Exception as e:
            return self._send_json({"success": False, "error": str(e)}, status=500)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        try:
            if path == "/api/eduboard/check":
                payload, status = check_eduboard_sync(self._read_json_body())
                return self._send_json(payload, status=status)

            if path == "/api/eboard/check":
                payload, status = check_eboard_sync(self._read_json_body())
                return self._send_json(payload, status=status)

            if path == "/api/ebr/check":
                payload, status = check_ebr_sync(self._read_json_body())
                return self._send_json(payload, status=status)

            if path == "/api/cache/check":
                payload, status = check_cache_sync(self._read_json_body())
                return self._send_json(payload, status=status)

            if path == "/api/check":
                return self._send_json({
                    "success": False,
                    "needs_eboard": True,
                    "error": "Please select Full Marks or All Boards and solve the visible Security Key.",
                })

            if path == "/api/sniper/start":
                data = self._read_json_body()
                if not str(data.get("roll", "")).strip():
                    return self._send_json({"success": False, "error": "Roll number is required."}, status=400)
                if not str(data.get("captcha", "")).strip():
                    return self._send_json({"success": False, "error": "Please solve the visible Security Key before starting."}, status=400)
                # Serverless runtimes cannot sustain persistent background threads; tell browser to run the retry loop
                return self._send_json({"success": True, "mode": "client", "message": "Client-side auto-retry monitor active."})

            if path == "/api/sniper/stop":
                return self._send_json({"success": True, "message": "Monitor stopped."})

            if path == "/api/search-pdf":
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                fields = _parse_multipart(self.headers.get("Content-Type", ""), body)
                roll = fields.get("roll", b"").decode("utf-8", errors="ignore").strip()
                pdf_bytes = fields.get("pdf", b"")
                if not roll:
                    return self._send_json({"success": False, "error": "Roll number is required."}, status=400)
                if not pdf_bytes or len(pdf_bytes) < 100:
                    return self._send_json({"success": False, "error": "Please upload a valid result PDF file."}, status=400)
                return self._send_json({"success": True, "data": parse_pdf_for_roll_sync(pdf_bytes, roll)})

            if path == "/api/profiles":
                new_p = self._read_json_body()
                new_p["id"] = f"p_{int(time.time() * 1000)}"
                profiles = read_profiles()
                profiles.append(new_p)
                write_profiles(profiles)
                return self._send_json({"success": True, "profile": new_p})

            return self._send_json({"success": False, "error": f"Endpoint not found: {path}"}, status=404)
        except Exception as e:
            return self._send_json({"success": False, "error": str(e)}, status=500)

    def do_DELETE(self):
        path = urlparse(self.path).path.rstrip("/")
        if path.startswith("/api/profiles/"):
            prof_id = path.split("/")[-1]
            profiles = [p for p in read_profiles() if p.get("id") != prof_id]
            write_profiles(profiles)
            return self._send_json({"success": True})
        return self._send_json({"success": False, "error": "Not found"}, status=404)
