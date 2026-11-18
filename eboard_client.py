import base64
import threading
import time
import uuid
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EboardClient:
    """Clean client for Bangladesh Education Board multi-board results via result.bangladeshgov.org."""

    BASE_URL = "https://result.bangladeshgov.org"

    def __init__(self):
        self.sessions = {}  # session_id -> {'session': requests.Session, 'created_at': float}
        self.ready_pool = []  # list of (session_id, data_uri)
        self.pool_lock = threading.Lock()
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, image/jpeg, text/html, */*",
            "Referer": f"{self.BASE_URL}/",
            "Origin": self.BASE_URL,
        }
        self.stop_worker = False
        self.worker_thread = threading.Thread(target=self._pool_worker, daemon=True)
        self.worker_thread.start()

    def _cleanup_old(self):
        now = time.time()
        expired = [sid for sid, data in list(self.sessions.items()) if now - data["created_at"] > 300]
        for sid in expired:
            self.sessions.pop(sid, None)

    def _fetch_one_session(self):
        s = requests.Session()
        s.verify = False
        t_now = int(time.time() * 1000)
        c_url = f"{self.BASE_URL}/captcha?t={t_now}"
        c_resp = s.get(c_url, headers=self.headers, timeout=12)
        c_resp.raise_for_status()

        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "session": s,
            "created_at": time.time(),
        }
        b64_img = base64.b64encode(c_resp.content).decode("ascii")
        return session_id, f"data:image/jpeg;base64,{b64_img}"

    def _pool_worker(self):
        while not self.stop_worker:
            try:
                self._cleanup_old()
                with self.pool_lock:
                    pool_len = len(self.ready_pool)
                if pool_len < 2:
                    sid, uri = self._fetch_one_session()
                    with self.pool_lock:
                        self.ready_pool.append((sid, uri))
                    time.sleep(1)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(3)

    def create_captcha_session(self):
        self._cleanup_old()
        with self.pool_lock:
            if self.ready_pool:
                return self.ready_pool.pop(0)
        return self._fetch_one_session()

    def get_result(self, session_id, board, exam, year, roll, reg, captcha):
        if session_id not in self.sessions:
            return {
                "success": False,
                "error": "Captcha session expired. Please refresh the security key. / ক্যাপচা সেশনের মেয়াদ শেষ হয়েছে, নতুন কোড রিলোড করুন।",
            }

        s = self.sessions[session_id]["session"]
        payload = {
            "result_type": "1",
            "exam": str(exam).lower().strip(),
            "year": str(year).strip(),
            "board": str(board).lower().strip(),
            "roll": str(roll).strip(),
            "reg": str(reg).strip(),
            "captcha": str(captcha).strip(),
        }

        resp = s.post(
            f"{self.BASE_URL}/result",
            data=payload,
            headers={**self.headers, "X-Requested-With": "XMLHttpRequest"},
            timeout=15,
        )

        try:
            res_json = resp.json()
        except Exception:
            return {
                "success": False,
                "error": f"Invalid server response ({resp.status_code}). Please retry with a fresh security key.",
            }

        if res_json.get("status") == 0:
            res_obj = dict(res_json.get("res") or {})
            if "sub_details" in res_json and "sub_details" not in res_obj:
                res_obj["sub_details"] = res_json["sub_details"]
            if "showmarks" in res_json:
                res_obj["showmarks"] = res_json["showmarks"]
            return {"success": True, "data": res_obj}

        err_msg = res_json.get("msg") or "Result not found or security key did not match."
        return {"success": False, "error": err_msg}


eboard_client = EboardClient()
