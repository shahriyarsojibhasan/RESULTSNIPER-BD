import urllib.request, ssl, json, re, time

class EduBoardClient:
    BOARD_MAP = {
        "dhaka": 10,
        "comilla": 11,
        "cumilla": 11,
        "rajshahi": 12,
        "jessore": 13,
        "jashore": 13,
        "chittagong": 14,
        "chattogram": 14,
        "barisal": 15,
        "sylhet": 16,
        "dinajpur": 17,
        "madrasah": 18,
        "technical": 19,
        "tec": 19,
        "mymensingh": 21
    }

    def __init__(self):
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Origin': 'https://eduboardresults.gov.bd',
            'Referer': 'https://eduboardresults.gov.bd/'
        }

    def get_captcha(self):
        try:
            url = 'https://eduboardresults.gov.bd/v1/captcha/generate-string-image-captcha'
            req = urllib.request.Request(url, headers=self.headers)
            res = urllib.request.urlopen(req, context=self.ctx, timeout=8)
            data = json.loads(res.read().decode('utf-8'))
            img_b64 = data.get('imageBase64', '')
            if not img_b64.startswith('data:'):
                img_b64 = f"data:image/png;base64,{img_b64}"

            return {
                "success": True,
                "captcha_img": img_b64,
                "hash": data.get('hash'),
                "timestamp": data.get('timestamp')
            }
        except Exception as e:
            return {"success": False, "error": f"ক্যাপচা লোড করা যায়নি: {str(e)}"}

    def get_result(self, board, year, roll, reg, captcha_text, hash_val, timestamp):
        try:
            b_key = str(board).strip().lower()
            board_id = self.BOARD_MAP.get(b_key, 10)
            if isinstance(board, int) or (isinstance(board, str) and board.isdigit()):
                board_id = int(board)

            url = 'https://eduboardresults.gov.bd/api/rescrutiny/getStudentResult'
            payload = {
                "rollNo": str(roll).strip(),
                "regNo": str(reg).strip(),
                "boardId": board_id,
                "passYear": int(year),
                "captchaText": str(captcha_text).strip(),
                "hash": hash_val,
                "timestamp": int(timestamp)
            }

            post_data = json.dumps(payload).encode('utf-8')
            req_headers = {**self.headers, 'Content-Type': 'application/json'}
            req = urllib.request.Request(url, data=post_data, headers=req_headers)
            res = urllib.request.urlopen(req, context=self.ctx, timeout=12)
            res_data = json.loads(res.read().decode('utf-8'))

            if res_data.get('status') == 200 and 'result' in res_data:
                inner = res_data['result']
                info = inner.get('info', {})
                result_str = inner.get('result', '')

                return {
                    "success": True,
                    "data": {
                        "raw_result_str": result_str,
                        "name": info.get('name', 'N/A'),
                        "father": info.get('fatherName', 'N/A'),
                        "mother": info.get('motherName', 'N/A'),
                        "roll": str(info.get('rollNo', roll)),
                        "reg": str(info.get('regNo', reg)),
                        "board": b_key.capitalize(),
                        "board_id": board_id,
                        "exam": "HSC",
                        "year": str(info.get('passYear', year)),
                        "gpa": str(info.get('gpa', 'N/A')),
                        "status": info.get('result', 'P'),
                        "group": info.get('groupName', 'N/A'),
                        "session": info.get('session') or info.get('sessionName') or 'N/A',
                        "college": info.get('instituteName') or info.get('institutionName') or 'N/A',
                        "eiin": str(info.get('eiin') or info.get('eiinNo') or info.get('instituteCode') or 'N/A'),
                        "type": info.get('type') or info.get('studentType') or 'REGULAR',
                        "source": "eduboardresults.gov.bd (শিক্ষা বোর্ড অফিসিয়াল ক্লাউড পোর্টাল)"
                    }
                }
            elif res_data.get('status') == 210:
                return {"success": False, "error": "Invalid captcha code! Please try again. / ক্যাপচা কোড ভুল হয়েছে!"}
            else:
                msg = res_data.get('message') or "Result not found. Verify Roll, Reg, Board and try again. / রেজাল্ট পাওয়া যায়নি।"
                return {"success": False, "error": msg}

        except urllib.error.HTTPError as e:
            return {"success": False, "error": f"Server error ({e.code}): Captcha expired or board server busy."}
        except Exception as e:
            return {"success": False, "error": f"Connection error: {str(e)}"}

eduboard_client = EduBoardClient()

