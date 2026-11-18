import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import os
import re
import sys
import time
import zlib
from aiohttp import web
import urllib3
import requests
from eboard_client import eboard_client
from eduboard_client import eduboard_client

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, 'public')
PROFILES_FILE = os.path.join(BASE_DIR, 'profiles.json')
SECRET_FILE = os.path.join(BASE_DIR, '.secret.key')

# ----------------- Marksheet Signing (QR Verification) -----------------
def _load_secret():
    env = os.environ.get('RS_SECRET')
    if env:
        return env.encode('utf-8')
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'w', encoding='utf-8') as f:
            f.write(secrets.token_hex(32))
    with open(SECRET_FILE, 'r', encoding='utf-8') as f:
        return f.read().strip().encode('utf-8')

SIGN_SECRET = _load_secret()

def _b64u(b):
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def sign_result(d):
    """Create a tamper-proof token from a result that was fetched from an official board server."""
    subs = ';'.join(f"{s.get('code','')}:{s.get('grade','')}:{s.get('total', s.get('marks','--'))}" for s in d.get('subjects', []))
    payload = {
        'n': d.get('name', ''), 'f': d.get('father', ''), 'm': d.get('mother', ''),
        'r': str(d.get('roll', '')), 'g': str(d.get('reg', '')), 'b': d.get('board', ''),
        'e': d.get('exam', ''), 'y': str(d.get('year', '')), 'p': str(d.get('gpa', '')),
        'gr': d.get('group', ''), 'i': d.get('college', ''), 'ei': str(d.get('eiin', '')),
        's': subs, 't': int(time.time())
    }
    body = _b64u(zlib.compress(json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), 9))
    sig = _b64u(hmac.new(SIGN_SECRET, body.encode('ascii'), hashlib.sha256).digest()[:16])
    return f"{body}.{sig}"

def verify_token(token):
    try:
        body, sig = token.strip().split('.', 1)
        expect = _b64u(hmac.new(SIGN_SECRET, body.encode('ascii'), hashlib.sha256).digest()[:16])
        if not hmac.compare_digest(sig, expect):
            return None
        return json.loads(zlib.decompress(_b64u_dec(body)).decode('utf-8'))
    except Exception:
        return None

def attach_verification(d):
    try:
        d['verify_token'] = sign_result(d)
        d['doc_id'] = 'RS-' + hashlib.sha256(d['verify_token'].encode()).hexdigest()[:10].upper()
    except Exception:
        pass
    return d

# Comprehensive Subject mapping for Bangladesh HSC / SSC (Single & Combined Codes)
HSC_SUBJECT_MAP = {
    # Compulsory
    "101": {"en": "Bangla I", "bn": "বাংলা ১ম পত্র"},
    "102": {"en": "Bangla II", "bn": "বাংলা ২য় পত্র"},
    "101-102": {"en": "Bangla", "bn": "বাংলা"},
    "107": {"en": "English I", "bn": "ইংরেজি ১ম পত্র"},
    "108": {"en": "English II", "bn": "ইংরেজি ২য় পত্র"},
    "107-108": {"en": "English", "bn": "ইংরেজি"},
    "154": {"en": "Information & Communication Technology", "bn": "তথ্য ও যোগাযোগ প্রযুক্তি"},
    "275": {"en": "Information & Communication Technology (ICT)", "bn": "তথ্য ও যোগাযোগ প্রযুক্তি"},
    # Science
    "174": {"en": "Physics I", "bn": "পদার্থবিজ্ঞান ১ম পত্র"},
    "175": {"en": "Physics II", "bn": "পদার্থবিজ্ঞান ২য় পত্র"},
    "174-175": {"en": "Physics", "bn": "পদার্থবিজ্ঞান"},
    "176": {"en": "Chemistry I", "bn": "রসায়ন ১ম পত্র"},
    "177": {"en": "Chemistry II", "bn": "রসায়ন ২য় পত্র"},
    "176-177": {"en": "Chemistry", "bn": "রসায়ন"},
    "178": {"en": "Biology I", "bn": "জীববিজ্ঞান ১ম পত্র"},
    "179": {"en": "Biology II", "bn": "জীববিজ্ঞান ২য় পত্র"},
    "178-179": {"en": "Biology", "bn": "জীববিজ্ঞান"},
    "265": {"en": "Higher Mathematics I", "bn": "উচ্চতর গণিত ১ম পত্র"},
    "266": {"en": "Higher Mathematics II", "bn": "উচ্চতর গণিত ২য় পত্র"},
    "265-266": {"en": "Higher Mathematics", "bn": "উচ্চতর গণিত"},
    "125": {"en": "Geography I", "bn": "ভূগোল ১ম পত্র"},
    "126": {"en": "Geography II", "bn": "ভূগোল ২য় পত্র"},
    "125-126": {"en": "Geography", "bn": "ভূগোল"},
    "127": {"en": "Statistics I", "bn": "পরিসংখ্যান ১ম পত্র"},
    "128": {"en": "Statistics II", "bn": "পরিসংখ্যান ২য় পত্র"},
    "127-128": {"en": "Statistics", "bn": "পরিসংখ্যান"},
    # Humanities
    "109": {"en": "Economics I", "bn": "অর্থনীতি ১ম পত্র"},
    "110": {"en": "Economics II", "bn": "অর্থনীতি ২য় পত্র"},
    "109-110": {"en": "Economics", "bn": "অর্থনীতি"},
    "267": {"en": "Civics & Good Governance I", "bn": "পৌরনীতি ও সুশাসন ১ম পত্র"},
    "268": {"en": "Civics & Good Governance II", "bn": "পৌরনীতি ও সুশাসন ২য় পত্র"},
    "267-268": {"en": "Civics & Good Governance", "bn": "পৌরনীতি ও সুশাসন"},
    "269": {"en": "Social Work I", "bn": "সমাজকর্ম ১ম পত্র"},
    "270": {"en": "Social Work II", "bn": "সমাজকর্ম ২য় পত্র"},
    "269-270": {"en": "Social Work", "bn": "সমাজকর্ম"},
    "271": {"en": "Sociology I", "bn": "সমাজবিজ্ঞান ১ম পত্র"},
    "272": {"en": "Sociology II", "bn": "সমাজবিজ্ঞান ২য় পত্র"},
    "271-272": {"en": "Sociology", "bn": "সমাজবিজ্ঞান"},
    "304": {"en": "History I", "bn": "ইতিহাস ১ম পত্র"},
    "305": {"en": "History II", "bn": "ইতিহাস ২য় পত্র"},
    "304-305": {"en": "History", "bn": "ইতিহাস"},
    "273": {"en": "Islamic History & Culture I", "bn": "ইসলামের ইতিহাস ও সংস্কৃতি ১ম পত্র"},
    "274": {"en": "Islamic History & Culture II", "bn": "ইসলামের ইতিহাস ২য় পত্র"},
    "273-274": {"en": "Islamic History & Culture", "bn": "ইসলামের ইতিহাস ও সংস্কৃতি"},
    "121": {"en": "Logic I", "bn": "যুক্তিবিদ্যা ১ম পত্র"},
    "122": {"en": "Logic II", "bn": "যুক্তিবিদ্যা ২য় পত্র"},
    "121-122": {"en": "Logic", "bn": "যুক্তিবিদ্যা"},
    "129": {"en": "Psychology I", "bn": "মনোবিজ্ঞান ১ম পত্র"},
    "130": {"en": "Psychology II", "bn": "মনোবিজ্ঞান ২য় পত্র"},
    "129-130": {"en": "Psychology", "bn": "মনোবিজ্ঞান"},
    "249": {"en": "Islamic Studies I", "bn": "ইসলাম শিক্ষা ১ম পত্র"},
    "250": {"en": "Islamic Studies II", "bn": "ইসলাম শিক্ষা ২য় পত্র"},
    "249-250": {"en": "Islamic Studies", "bn": "ইসলাম শিক্ষা"},
    "282": {"en": "Home Science I", "bn": "গার্হস্থ্য বিজ্ঞান ১ম পত্র"},
    "283": {"en": "Home Science II", "bn": "গার্হস্থ্য বিজ্ঞান ২য় পত্র"},
    "282-283": {"en": "Home Science", "bn": "গার্হস্থ্য বিজ্ঞান"},
    # Business Studies
    "253": {"en": "Accounting I", "bn": "হিসাববিজ্ঞান ১ম পত্র"},
    "254": {"en": "Accounting II", "bn": "হিসাববিজ্ঞান ২য় পত্র"},
    "253-254": {"en": "Accounting", "bn": "হিসাববিজ্ঞান"},
    "277": {"en": "Business Organization & Management I", "bn": "ব্যবসায় সংগঠন ১ম পত্র"},
    "278": {"en": "Business Organization & Management II", "bn": "ব্যবসায় সংগঠন ২য় পত্র"},
    "277-278": {"en": "Business Organization & Management", "bn": "ব্যবসায় সংগঠন ও ব্যবস্থাপনা"},
    "292": {"en": "Finance, Banking & Insurance I", "bn": "ফিন্যান্স ১ম পত্র"},
    "293": {"en": "Finance, Banking & Insurance II", "bn": "ফিন্যান্স ২য় পত্র"},
    "292-293": {"en": "Finance, Banking & Insurance", "bn": "ফিন্যান্স, ব্যাংকিং ও বিমা"},
    "290": {"en": "Production Management & Marketing I", "bn": "উৎপাদন ব্যবস্থাপনা ১ম পত্র"},
    "291": {"en": "Production Management & Marketing II", "bn": "উৎপাদন ব্যবস্থাপনা ২য় পত্র"},
    "290-291": {"en": "Production Management & Marketing", "bn": "উৎপাদন ব্যবস্থাপনা ও বিপণন"},
    # SSC
    "111": {"en": "Islam & Moral Education", "bn": "ইসলাম ও নৈতিক শিক্ষা"},
    "112": {"en": "Hindu Religion & Moral Education", "bn": "হিন্দুধর্ম ও নৈতিক শিক্ষা"},
    "136": {"en": "Physics (SSC)", "bn": "পদার্থবিজ্ঞান"},
    "137": {"en": "Chemistry (SSC)", "bn": "রসায়ন"},
    "138": {"en": "Biology (SSC)", "bn": "জীববিজ্ঞান"},
    "143": {"en": "Accounting (SSC)", "bn": "হিসাববিজ্ঞান"},
    "144": {"en": "Business Ent. (SSC)", "bn": "ব্যবসায় উদ্যোগ"},
    "145": {"en": "Finance & Banking (SSC)", "bn": "ফিন্যান্স ও ব্যাংকিং"},
    "150": {"en": "Bangladesh & Global Studies", "bn": "বাংলাদেশ ও বিশ্বপরিচয়"},
    "153": {"en": "General Science", "bn": "সাধারণ বিজ্ঞান"},
    "133": {"en": "Agriculture Studies", "bn": "কৃষিশিক্ষা"},
    "151": {"en": "Home Science (SSC)", "bn": "গার্হস্থ্য বিজ্ঞান"},
}

GRADE_POINT_MAP = {
    "A+": "5.00",
    "A": "4.00",
    "A-": "3.50",
    "B": "3.00",
    "C": "2.00",
    "D": "1.00",
    "F": "0.00"
}

def parse_subjects(display_details):
    subjects = []
    if not display_details:
        return subjects

    items = []
    if isinstance(display_details, str):
        items = [x.strip() for x in display_details.split(',') if x.strip()]
    elif isinstance(display_details, list):
        items = display_details

    for item in items:
        # Check if item is list e.g. ["101", "Bangla", "A+", "85"]
        if isinstance(item, list) and len(item) >= 3:
            code = str(item[0]).strip()
            grade = str(item[2]).strip()
            total_marks = str(item[3]).strip() if len(item) > 3 else "--"
            sub_info = HSC_SUBJECT_MAP.get(code, {"en": f"Subject {code}", "bn": f"বিষয় {code}"})
            gp = GRADE_POINT_MAP.get(grade, "--")
            subjects.append({
                "code": code,
                "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'],
                "name_en": sub_info['en'],
                "cq": "--", "cq_total": "--",
                "mcq": "--", "mcq_total": "--",
                "practical": "--", "practical_total": "--",
                "total": total_marks if total_marks else "--",
                "marks": total_marks if total_marks else "--",
                "grade": grade,
                "gp": gp,
                "papers": []
            })
            continue

        item_str = str(item).strip()
        code = ""
        grade = ""
        total_marks = "--"
        cq = "--"
        cq_total = "--"
        mcq = "--"
        mcq_total = "--"
        practical = "--"
        practical_total = "--"
        paper_details = []
        raw_name = ""

        # FORMAT 1: eduboard format: "101-102 A BANGLA 139" or "275 A INFORMATION & COMMUNICATION TECHNOLOGY 073"
        m_edu = re.match(r'^([\d\-]+)\s+([A-F][\+\-]?)\s+(.+?)\s+(\d+)$', item_str)
        if m_edu:
            code = m_edu.group(1).strip()
            grade = m_edu.group(2).strip()
            raw_name = m_edu.group(3).strip().title()
            total_marks = str(int(m_edu.group(4).strip()))

            sub_info = HSC_SUBJECT_MAP.get(code)
            if not sub_info:
                base_code = code.split('-')[0]
                sub_info = HSC_SUBJECT_MAP.get(base_code, {"en": raw_name, "bn": raw_name})

            gp = GRADE_POINT_MAP.get(grade, "--")
            subjects.append({
                "code": code,
                "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'],
                "name_en": sub_info['en'],
                "cq": "--", "cq_total": "--",
                "mcq": "--", "mcq_total": "--",
                "practical": "--", "practical_total": "--",
                "total": total_marks,
                "marks": total_marks,
                "grade": grade,
                "gp": gp,
                "papers": []
            })
            continue

        # FORMAT 2: Colon format e.g. "101-102:133=A-", "107-108:146=A", "275:091=A+", "101-102:A", "174=42+25...=179:A+"
        if ':' in item_str:
            left, right = item_str.split(':', 1)
            left = left.strip()
            right = right.strip()

            # Check if right is "[marks]=[grade]" e.g. "133=A-" or "091=A+"
            if '=' in right:
                r_parts = right.split('=')
                grade = r_parts[-1].strip()
                marks_part = r_parts[0].strip()
                if marks_part.isdigit():
                    total_marks = str(int(marks_part))
                code = left
            else:
                grade = right

            # Check if left has "=" (e.g. 174=42+25+21-45+24+22=179 or 101=85)
            if '=' in left:
                l_parts = left.split('=')
                code = l_parts[0].strip()
                if len(l_parts) > 2:
                    # code=details=total
                    mrks_dtls = l_parts[1].strip()
                    total_marks = l_parts[2].strip()

                    papers = mrks_dtls.split('-')
                    for p_idx, paper in enumerate(papers):
                        parts = paper.split('+')
                        p_cq = parts[0].strip() if len(parts) > 0 else ""
                        p_prac = parts[1].strip() if len(parts) > 1 else ""
                        p_mcq = parts[2].strip() if len(parts) > 2 else ""

                        paper_details.append({
                            "paper": p_idx + 1,
                            "cq": p_cq,
                            "practical": p_prac,
                            "mcq": p_mcq
                        })

                    cq_list = [p['cq'] for p in paper_details if p['cq'] != '']
                    prac_list = [p['practical'] for p in paper_details if p['practical'] and p['practical'] != '0']
                    mcq_list = [p['mcq'] for p in paper_details if p['mcq'] != '']

                    def format_parts(p_list):
                        if not p_list: return "--", "--"
                        if len(p_list) == 1: return p_list[0], p_list[0]
                        try:
                            num_sum = sum(int(x) for x in p_list)
                            return " + ".join(p_list), str(num_sum)
                        except ValueError:
                            return " + ".join(p_list), "--"

                    cq, cq_total = format_parts(cq_list)
                    practical, practical_total = format_parts(prac_list)
                    mcq, mcq_total = format_parts(mcq_list)

                elif len(l_parts) == 2:
                    val = l_parts[1].strip()
                    if val.isdigit():
                        total_marks = str(int(val))
            else:
                code = left

            # Clean grade if '=' still in it
            if '=' in grade:
                g_parts = grade.split('=')
                grade = g_parts[-1].strip()
                if total_marks == "--" and g_parts[0].strip().isdigit():
                    total_marks = str(int(g_parts[0].strip()))

            sub_info = HSC_SUBJECT_MAP.get(code)
            if not sub_info:
                base_code = code.split('-')[0]
                sub_info = HSC_SUBJECT_MAP.get(base_code, {"en": f"Subject {code}", "bn": f"বিষয় {code}"})

            gp = GRADE_POINT_MAP.get(grade, "--")
            subjects.append({
                "code": code,
                "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'],
                "name_en": sub_info['en'],
                "cq": cq,
                "cq_total": cq_total,
                "mcq": mcq,
                "mcq_total": mcq_total,
                "practical": practical,
                "practical_total": practical_total,
                "total": total_marks if total_marks else "--",
                "marks": total_marks if total_marks else "--",
                "grade": grade,
                "gp": gp,
                "papers": paper_details
            })
            continue

        # FORMAT 3: Equal only format e.g. "101-102=133=A-"
        if '=' in item_str:
            eqs = item_str.split('=')
            code = eqs[0].strip()
            grade = eqs[-1].strip()
            if len(eqs) > 2 and eqs[1].strip().isdigit():
                total_marks = str(int(eqs[1].strip()))

            sub_info = HSC_SUBJECT_MAP.get(code)
            if not sub_info:
                base_code = code.split('-')[0]
                sub_info = HSC_SUBJECT_MAP.get(base_code, {"en": f"Subject {code}", "bn": f"বিষয় {code}"})

            gp = GRADE_POINT_MAP.get(grade, "--")
            subjects.append({
                "code": code,
                "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'],
                "name_en": sub_info['en'],
                "cq": cq, "cq_total": cq_total,
                "mcq": mcq, "mcq_total": mcq_total,
                "practical": practical, "practical_total": practical_total,
                "total": total_marks if total_marks else "--",
                "marks": total_marks if total_marks else "--",
                "grade": grade,
                "gp": gp,
                "papers": []
            })
            continue

    return subjects

# Initialize empty profiles if not exists
if not os.path.exists(PROFILES_FILE):
    with open(PROFILES_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f, indent=2, ensure_ascii=False)

# Global Sniper state
sniper_state = {
    "status": "IDLE",
    "params": None,
    "attempts": 0,
    "start_time": None,
    "last_attempt_time": None,
    "last_status": "Idle",
    "result": None,
    "logs": []
}
sniper_task = None

def add_sniper_log(msg):
    t_str = time.strftime('%H:%M:%S')
    log_entry = f"[{t_str}] {msg}"
    sniper_state["logs"].append(log_entry)
    if len(sniper_state["logs"]) > 100:
        sniper_state["logs"].pop(0)

# ----------------- Dhaka Board e-File Direct Gateway -----------------
def fetch_dhaka_board_sync(exam, year, roll, reg):
    session = requests.Session()
    session.verify = False
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }

    r = session.get('https://efile.dhakaeducationboard.gov.bd/index.php/document', headers=headers, timeout=12)
    m = re.search(r'var challenge = ({.*?});', r.text)
    if m:
        chal = json.loads(m.group(1))
        proof_str = f"browser-proof:{chal['seed']}:{chal['salt']}"
        hash_val = hashlib.sha256(proof_str.encode('utf-8')).hexdigest()
        answer = f"hash:{hash_val}"
        verify_url = 'https://efile.dhakaeducationboard.gov.bd/_challenge-verify'
        session.post(
            verify_url,
            json={'token': chal['token'], 'answer': answer},
            headers={**headers, 'Referer': r.url},
            timeout=12
        )

    url = 'https://efile.dhakaeducationboard.gov.bd/index.php/document/form3/js'
    data = {
        'exam': exam,
        'year': str(year),
        'roll': str(roll),
        'reg': str(reg),
        'an_id': '10'
    }
    resp = session.post(
        url,
        data=data,
        headers={
            **headers,
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'https://efile.dhakaeducationboard.gov.bd/index.php/document'
        },
        timeout=12
    )

    if resp.status_code == 429:
        return {"status": "RATE_LIMITED", "error": "Server is rate-limiting (429 Too Many Requests). Retrying..."}

    if 'Data Not Found' in resp.text:
        return {"status": "NOT_FOUND", "error": "Result / Data not found for this Roll & Registration combination."}

    if resp.status_code == 200 and len(resp.text) > 100:
        details = {}
        inputs = re.findall(r'<input[^>]+>', resp.text)
        for inp in inputs:
            name_m = re.search(r'name=["\'](.*?)["\']', inp)
            val_m = re.search(r'value=["\'](.*?)["\']', inp)
            if name_m and val_m:
                details[name_m.group(1)] = val_m.group(1)

        result_obj = {
            "source": "Dhaka Board Direct Gateway",
            "name": details.get("name", "N/A"),
            "father": details.get("father", "N/A"),
            "mother": details.get("mother", "N/A"),
            "roll": str(roll),
            "reg": str(reg),
            "exam": exam,
            "year": str(year),
            "board": "Dhaka",
            "gpa": details.get("result", "N/A").replace("GPA=", "").strip("[]"),
            "session": details.get("session", "N/A"),
            "college": details.get("institute", "N/A"),
            "eiin": details.get("eiin", "N/A"),
            "centre_code": details.get("c_code", "N/A"),
            "subjects": []
        }
        return {"status": "FOUND", "data": result_obj}

    return {"status": "ERROR", "error": f"Unexpected server response (Code: {resp.status_code})"}

# ----------------- eduboardresults.gov.bd Handlers (New Cloud API with Marks) -----------------
async def eduboard_captcha_endpoint(request):
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, eduboard_client.get_captcha)
        return web.json_response(data)
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def eduboard_check_endpoint(request):
    try:
        data = await request.json()
        board = data.get("board", "dhaka").strip().lower()
        year = str(data.get("year", "2026")).strip()
        roll = str(data.get("roll", "")).strip()
        reg = str(data.get("reg", "")).strip()
        captcha = str(data.get("captcha", "")).strip()
        hash_val = data.get("hash", "")
        timestamp = data.get("timestamp", 0)

        if not roll or not reg or not captcha:
            return web.json_response({"success": False, "error": "রোল নম্বর, রেজিস্ট্রেশন নম্বর এবং সিকিউরিটি কোড আবশ্যক।"}, status=400)

        loop = asyncio.get_event_loop()
        res = await loop.run_in_executor(
            None,
            eduboard_client.get_result,
            board, year, roll, reg, captcha, hash_val, timestamp
        )

        if res["success"]:
            student_data = res["data"]
            # Parse subjects with total marks
            subjects = parse_subjects(student_data.get("raw_result_str", ""))
            student_data["subjects"] = subjects
            student_data["source"] = "eduboardresults.gov.bd"
            student_data["exam"] = str(data.get("exam", "hsc")).upper()
            student_data.pop("raw_result_str", None)
            attach_verification(student_data)
            return web.json_response({"success": True, "data": student_data})
        else:
            return web.json_response({"success": False, "error": res.get("error", "রেজাল্ট পাওয়া যায়নি অথবা কোড সঠিক নয়।")})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

# ----------------- eboardresults.com Handlers -----------------
async def eboard_captcha_endpoint(request):
    try:
        loop = asyncio.get_event_loop()
        sid, uri = await loop.run_in_executor(None, eboard_client.create_captcha_session)
        return web.json_response({"success": True, "session_id": sid, "captcha_img": uri})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def eboard_check_endpoint(request):
    try:
        data = await request.json()
        session_id = data.get("session_id", "").strip()
        board = data.get("board", "rajshahi").strip().lower()
        exam = data.get("exam", "hsc").strip().lower()
        year = str(data.get("year", "2026")).strip()
        roll = str(data.get("roll", "")).strip()
        reg = str(data.get("reg", "")).strip()
        captcha = str(data.get("captcha", "")).strip()

        if not session_id or not roll or not captcha:
            return web.json_response({"success": False, "error": "রোল, সিকিউরিটি কি এবং সেশন প্রয়োজন।"}, status=400)

        loop = asyncio.get_event_loop()
        res = await loop.run_in_executor(
            None,
            eboard_client.get_result,
            session_id, board, exam, year, roll, reg, captcha
        )

        if res["success"]:
            raw = res["data"]
            # Parse subjects / marksheet
            display_details = raw.get("display_details") or raw.get("log_display_details") or ""
            subjects = parse_subjects(display_details)

            normalized = {
                "source": "eboardresults.com (All Boards Official API)",
                "name": raw.get("name", "N/A"),
                "father": raw.get("fname", "N/A"),
                "mother": raw.get("mname", "N/A"),
                "roll": raw.get("roll_no", roll),
                "reg": raw.get("regno", reg),
                "board": raw.get("board_name", board.capitalize()),
                "exam": exam.upper(),
                "year": str(year),
                "gpa": raw.get("gpa") or (f"Passed ({raw.get('res_detail')})" if raw.get("res_detail") == "P" else raw.get("res_detail", "N/A")),
                "session": raw.get("session", "N/A"),
                "college": raw.get("inst_name") or f"EIIN: {raw.get('eiin', 'N/A')}",
                "eiin": raw.get("eiin", "N/A"),
                "group": raw.get("stud_group", "N/A"),
                "subjects": subjects
            }
            attach_verification(normalized)
            return web.json_response({"success": True, "data": normalized})
        else:
            return web.json_response({"success": False, "error": res.get("error", "রেজাল্ট পাওয়া যায়নি অথবা সিকিউরিটি কি সঠিক নয়।")})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

# ----------------- Check Result Unified -----------------
async def check_result_endpoint(request):
    try:
        data = await request.json()
        board = data.get("board", "dhaka").strip().lower()
        exam = data.get("exam", "HSC").strip()
        year = str(data.get("year", "2026")).strip()
        roll = str(data.get("roll", "")).strip()
        reg = str(data.get("reg", "")).strip()

        if not roll:
            return web.json_response({"success": False, "error": "Roll is required."}, status=400)

        # If board is Dhaka and reg is provided, we can use the instant direct gateway
        if board == 'dhaka' and reg:
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(None, fetch_dhaka_board_sync, exam, year, roll, reg)
            if res["status"] == "FOUND":
                return web.json_response({"success": True, "data": res["data"]})
            else:
                return web.json_response({"success": False, "status": res["status"], "error": res.get("error", "Not found")})
        else:
            return web.json_response({
                "success": False,
                "needs_eboard": True,
                "error": f"For {board.capitalize()} Board, please use the eboardresults.com portal with the 4-digit security key below."
            })
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

# ----------------- Sniper Endpoints -----------------
async def sniper_worker():
    global sniper_state
    params = sniper_state["params"]
    board = params.get("board", "dhaka").lower()
    exam = params["exam"]
    year = params["year"]
    roll = params["roll"]
    reg = params["reg"]
    interval = max(3, params.get("interval", 5))

    add_sniper_log(f"Sniper started for Roll: {roll}, Reg: {reg}, Board: {board.capitalize()}, Exam: {exam}-{year}")
    loop = asyncio.get_event_loop()

    if board != 'dhaka':
        add_sniper_log(f"⚠️ লক্ষ্য করুন: অটো-বট মোড সরাসরি ঢাকা বোর্ডের জিরো-ক্যাপচা গেটওয়ে ব্যবহার করে। {board.capitalize()} বোর্ডের রেজাল্ট চেক করতে 'ওয়েব রেজাল্ট (eboardresults)' ট্যাবে যান।")

    while sniper_state["status"] == "RUNNING":
        sniper_state["attempts"] += 1
        sniper_state["last_attempt_time"] = time.strftime('%H:%M:%S')

        try:
            if board == 'dhaka':
                res = await loop.run_in_executor(None, fetch_dhaka_board_sync, exam, year, roll, reg)
                if res["status"] == "FOUND":
                    sniper_state["status"] = "FOUND"
                    sniper_state["result"] = attach_verification(res["data"])
                    sniper_state["last_status"] = "Result Published & Captured!"
                    add_sniper_log(f"🔥 RESULT CAPTURED! GPA: {res['data'].get('gpa')} for {res['data'].get('name')}")
                    break
                elif res["status"] == "NOT_FOUND":
                    sniper_state["last_status"] = "Not published yet / Pending"
                    add_sniper_log(f"Attempt #{sniper_state['attempts']}: Result not available yet. Retrying in {interval}s...")
                elif res["status"] == "RATE_LIMITED":
                    sniper_state["last_status"] = "Rate-limited (waiting cooldown)"
                    add_sniper_log(f"Attempt #{sniper_state['attempts']}: 429 Rate limit. Backing off 8s...")
                    await asyncio.sleep(8)
                    continue
                else:
                    sniper_state["last_status"] = res.get("error", "Server Busy")
                    add_sniper_log(f"Attempt #{sniper_state['attempts']}: {sniper_state['last_status']}")
            else:
                # Non-dhaka board sniper explanation
                sniper_state["last_status"] = f"বোর্ড {board.capitalize()}: eboardresults ট্যাব ব্যবহার করুন"
                add_sniper_log(f"Attempt #{sniper_state['attempts']}: {board.capitalize()} বোর্ডের জন্য eboardresults ট্যাবে ৪-ডিজিটের সিকিউরিটি কি দিয়ে চেক করুন।")
                await asyncio.sleep(interval)
        except Exception as e:
            sniper_state["last_status"] = f"Network Error: {str(e)}"
            add_sniper_log(f"Attempt #{sniper_state['attempts']} Error: {str(e)}")

        await asyncio.sleep(interval)

async def sniper_start_endpoint(request):
    global sniper_state, sniper_task
    data = await request.json()
    roll = str(data.get("roll", "")).strip()
    reg = str(data.get("reg", "")).strip()
    board = str(data.get("board", "dhaka")).strip().lower()
    exam = data.get("exam", "HSC").strip()
    year = str(data.get("year", "2026")).strip()
    interval = int(data.get("interval", 5))

    if not roll:
        return web.json_response({"success": False, "error": "Roll is required."}, status=400)

    if sniper_task and not sniper_task.done():
        sniper_state["status"] = "STOPPED"
        sniper_task.cancel()

    sniper_state = {
        "status": "RUNNING",
        "params": {"roll": roll, "reg": reg, "board": board, "exam": exam, "year": year, "interval": interval},
        "attempts": 0,
        "start_time": time.strftime('%H:%M:%S'),
        "last_attempt_time": None,
        "last_status": "Starting sniper loop...",
        "result": None,
        "logs": []
    }

    sniper_task = asyncio.create_task(sniper_worker())
    return web.json_response({"success": True, "message": "Sniper monitoring initiated."})

async def sniper_stop_endpoint(request):
    global sniper_state, sniper_task
    if sniper_task and not sniper_task.done():
        sniper_state["status"] = "STOPPED"
        sniper_task.cancel()
        add_sniper_log("Sniper stopped by user.")
    return web.json_response({"success": True, "message": "Sniper stopped."})

async def sniper_status_endpoint(request):
    return web.json_response({
        "status": sniper_state["status"],
        "attempts": sniper_state["attempts"],
        "start_time": sniper_state["start_time"],
        "last_attempt_time": sniper_state["last_attempt_time"],
        "last_status": sniper_state["last_status"],
        "result": sniper_state["result"],
        "logs": sniper_state["logs"][-30:]
    })

# ----------------- PDF Search -----------------
def parse_pdf_for_roll_sync(pdf_bytes, target_roll):
    stream_pattern = re.compile(rb'stream[\r\n]+(.*?)[\r\n]+endstream', re.DOTALL)
    full_text = []
    for match in stream_pattern.finditer(pdf_bytes):
        try:
            full_text.append(zlib.decompress(match.group(1)).decode('latin1', errors='ignore'))
        except Exception:
            pass
    combined = '\n'.join(full_text)

    inst_match = re.search(r'Institution:\s*([^\n\r\(\)]+)', combined)
    eiin_match = re.search(r'EIIN:\s*(\d+)', combined)
    institution = inst_match.group(1).strip() if inst_match else "Unknown Institution"
    eiin = eiin_match.group(1).strip() if eiin_match else "N/A"

    pattern = rf'{target_roll}(?:\\133|\[)([\d\.]+)(?:\\135|\])'
    m = re.search(pattern, combined)
    if m:
        return {
            "found": True,
            "roll": target_roll,
            "gpa": m.group(1),
            "institution": institution,
            "eiin": eiin
        }

    fail_pattern = rf'{target_roll}(?:\\133|\[)([^\]\\]+)(?:\\135|\])'
    mf = re.search(fail_pattern, combined)
    if mf:
        return {
            "found": True,
            "roll": target_roll,
            "gpa": "FAIL",
            "detail": mf.group(1),
            "institution": institution,
            "eiin": eiin
        }

    return {"found": False, "institution": institution, "eiin": eiin}

async def search_pdf_endpoint(request):
    try:
        reader = await request.multipart()
        target_roll = ""
        pdf_bytes = None

        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == 'roll':
                target_roll = (await part.text()).strip()
            elif part.name == 'pdf':
                pdf_bytes = await part.read()

        if not target_roll:
            return web.json_response({"success": False, "error": "রোল নম্বর প্রদান আবশ্যক।"}, status=400)

        if not pdf_bytes or len(pdf_bytes) < 100:
            return web.json_response({"success": False, "error": "অনুগ্রহ করে একটি ফলাফল পিডিএফ (.pdf) ফাইল আপলোড করুন।"}, status=400)

        loop = asyncio.get_event_loop()
        res = await loop.run_in_executor(None, parse_pdf_for_roll_sync, pdf_bytes, target_roll)
        return web.json_response({"success": True, "data": res})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

# ----------------- Profiles -----------------
async def get_profiles_endpoint(request):
    try:
        with open(PROFILES_FILE, 'r', encoding='utf-8') as f:
            profiles = json.load(f)
        return web.json_response({"success": True, "profiles": profiles})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def save_profile_endpoint(request):
    try:
        new_profile = await request.json()
        new_profile["id"] = f"p_{int(time.time()*1000)}"
        with open(PROFILES_FILE, 'r', encoding='utf-8') as f:
            profiles = json.load(f)
        profiles.append(new_profile)
        with open(PROFILES_FILE, 'w', encoding='utf-8') as f:
            json.dump(profiles, f, indent=2, ensure_ascii=False)
        return web.json_response({"success": True, "profile": new_profile})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def delete_profile_endpoint(request):
    try:
        prof_id = request.match_info.get('id', '')
        with open(PROFILES_FILE, 'r', encoding='utf-8') as f:
            profiles = json.load(f)
        profiles = [p for p in profiles if p.get('id') != prof_id]
        with open(PROFILES_FILE, 'w', encoding='utf-8') as f:
            json.dump(profiles, f, indent=2, ensure_ascii=False)
        return web.json_response({"success": True})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

NO_CACHE = {
    'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'Expires': '0'
}

async def index_handler(request):
    return web.FileResponse(os.path.join(PUBLIC_DIR, 'index.html'), headers=NO_CACHE)

async def verify_api_endpoint(request):
    token = request.query.get('t', '').strip()
    raw = verify_token(token) if token else None
    if not raw:
        return web.json_response({"valid": False, "error": "Invalid or tampered marksheet token."})

    subs = []
    if raw.get('s'):
        for item in raw['s'].split(';'):
            if not item:
                continue
            parts = item.split(':')
            code = parts[0] if len(parts) > 0 else ''
            grade = parts[1] if len(parts) > 1 else ''
            marks = parts[2] if len(parts) > 2 else ''
            sub_meta = HSC_SUBJECT_MAP.get(code, {})
            subs.append({
                'code': code,
                'name_en': sub_meta.get('en', f'Subject {code}'),
                'name_bn': sub_meta.get('bn', f'বিষয় {code}'),
                'grade': grade,
                'marks': marks,
                'total': marks
            })

    doc_id = 'RS-' + hashlib.sha256(token.encode()).hexdigest()[:10].upper()
    data = {
        'doc_id': doc_id,
        'name': raw.get('n', ''),
        'father': raw.get('f', ''),
        'mother': raw.get('m', ''),
        'roll': raw.get('r', ''),
        'reg': raw.get('g', ''),
        'board': raw.get('b', ''),
        'exam': raw.get('e', ''),
        'year': raw.get('y', ''),
        'gpa': raw.get('p', ''),
        'group': raw.get('gr', ''),
        'college': raw.get('i', ''),
        'eiin': raw.get('ei', ''),
        'subjects': subs,
        'issued_at': raw.get('t', 0),
        'token': token
    }
    return web.json_response({"valid": True, "data": data})

# Clean public pages: /about, /terms, /privacy, /verify + root files (llms.txt, robots.txt, ...)
PAGE_MAP = {
    'about': 'about.html', 'terms': 'terms.html', 'privacy': 'privacy.html',
    'privacy-policy': 'privacy.html', 'verify': 'verify.html',
}
ROOT_FILES = {'llms.txt', 'robots.txt', 'sitemap.xml', 'favicon.svg', 'favicon.ico',
              'site.webmanifest', 'humans.txt', 'about.html', 'terms.html', 'privacy.html', 'verify.html'}

async def page_handler(request):
    name = request.match_info.get('name', '').strip('/').lower()
    fname = PAGE_MAP.get(name) or (name if name in ROOT_FILES else None)
    if not fname:
        raise web.HTTPNotFound(text="404 - Page not found")
    path = os.path.join(PUBLIC_DIR, fname)
    if fname == 'favicon.ico':
        path = os.path.join(PUBLIC_DIR, 'favicon.svg')
    if not os.path.exists(path):
        raise web.HTTPNotFound(text="404 - Page not found")
    headers = dict(NO_CACHE) if fname.endswith('.html') else {}
    if fname.endswith('.txt'):
        headers['Content-Type'] = 'text/plain; charset=utf-8'
    return web.FileResponse(path, headers=headers)

def create_app():
    app = web.Application(client_max_size=50*1024*1024)
    app.router.add_get('/', index_handler)
    app.router.add_get('/api/verify', verify_api_endpoint)
    app.router.add_post('/api/check', check_result_endpoint)
    app.router.add_get('/api/eduboard/captcha', eduboard_captcha_endpoint)
    app.router.add_post('/api/eduboard/check', eduboard_check_endpoint)
    app.router.add_get('/api/eboard/captcha', eboard_captcha_endpoint)
    app.router.add_post('/api/eboard/check', eboard_check_endpoint)
    app.router.add_post('/api/sniper/start', sniper_start_endpoint)
    app.router.add_post('/api/sniper/stop', sniper_stop_endpoint)
    app.router.add_get('/api/sniper/status', sniper_status_endpoint)
    app.router.add_post('/api/search-pdf', search_pdf_endpoint)
    app.router.add_get('/api/profiles', get_profiles_endpoint)
    app.router.add_post('/api/profiles', save_profile_endpoint)
    app.router.add_delete('/api/profiles/{id}', delete_profile_endpoint)
    app.router.add_static('/assets', os.path.join(PUBLIC_DIR, 'assets'))
    app.router.add_get('/{name}', page_handler)
    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print(f"=======================================================")
    print(f"ResultSniper BD is running at: http://localhost:{port}")
    print(f"=======================================================")
    app = create_app()
    web.run_app(app, host='0.0.0.0', port=port)
