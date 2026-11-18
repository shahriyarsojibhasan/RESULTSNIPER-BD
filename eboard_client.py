import requests, json, hashlib, re, time, base64, uuid, threading

class EboardClient:
    def __init__(self):
        self.sessions = {} # session_id -> { 'session': requests.Session, 'created_at': float }
        self.ready_pool = [] # list of (session_id, data_uri)
        self.pool_lock = threading.Lock()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        # Start background pool replenisher
        self.stop_worker = False
        self.worker_thread = threading.Thread(target=self._pool_worker, daemon=True)
        self.worker_thread.start()

    def _cleanup_old(self):
        now = time.time()
        expired = [sid for sid, data in self.sessions.items() if now - data['created_at'] > 300]
        for sid in expired:
            del self.sessions[sid]

    def _fetch_one_session(self):
        s = requests.Session()
        s.verify = False

        r = s.get('https://eboardresults.com/v2/home', headers=self.headers, timeout=12)
        m = re.search(r'var challenge = ({.*?});', r.text)
        if m:
            chal = json.loads(m.group(1))
            proof_str = f"browser-proof:{chal['seed']}:{chal['salt']}"
            hash_val = hashlib.sha256(proof_str.encode('utf-8')).hexdigest()
            answer = f"hash:{hash_val}"
            verify_url = 'https://eboardresults.com/_challenge-verify'
            s.post(
                verify_url,
                json={'token': chal['token'], 'answer': answer},
                headers={**self.headers, 'Referer': r.url},
                timeout=12
            )
            s.get('https://eboardresults.com/v2/home', headers=self.headers, timeout=12)

        t_now = int(time.time() * 1000)
        c_url = f'https://eboardresults.com/v2/captcha?t={t_now}'
        c_resp = s.get(c_url, headers={**self.headers, 'Referer': 'https://eboardresults.com/v2/home'}, timeout=12)

        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'session': s,
            'created_at': time.time()
        }

        b64_img = base64.b64encode(c_resp.content).decode('ascii')
        data_uri = f"data:image/jpeg;base64,{b64_img}"
        return session_id, data_uri

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
                    # Wait a little between fetches
                    time.sleep(1)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(3)

    def create_captcha_session(self):
        self._cleanup_old()
        with self.pool_lock:
            if self.ready_pool:
                sid, uri = self.ready_pool.pop(0)
                return sid, uri

        # Fallback to synchronous fetch if pool was empty
        return self._fetch_one_session()

    def get_result(self, session_id, board, exam, year, roll, reg, captcha):
        if session_id not in self.sessions:
            return {"success": False, "error": "ক্যাপচা সেশনের মেয়াদ শেষ হয়ে গেছে। অনুগ্রহ করে নতুন সিকিউরিটি কি রিলোড করুন।"}

        s_data = self.sessions[session_id]
        s = s_data['session']

        url = 'https://eboardresults.com/v2/getres'
        data = {
            'board': str(board).lower(),
            'exam': str(exam).lower(),
            'year': str(year),
            'result_type': '1',
            'roll': str(roll),
            'reg': str(reg),
            'captcha': str(captcha).strip()
        }

        resp = s.post(
            url,
            data=data,
            headers={
                **self.headers,
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': 'https://eboardresults.com/v2/home'
            },
            timeout=15
        )

        try:
            res_json = resp.json()
        except Exception:
            return {"success": False, "error": f"সার্ভার থেকে সঠিক তথ্য পাওয়া যায়নি: {resp.text[:150]}"}

        if res_json.get("status") == 0:
            return {"success": True, "data": res_json.get("res", {})}
        else:
            return {"success": False, "error": res_json.get("msg", "রেজাল্ট পাওয়া যায়নি অথবা সিকিউরিটি কি সঠিক নয়।")}

eboard_client = EboardClient()
