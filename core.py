import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

from eboard_client import eboard_client
from eduboard_client import eduboard_client
from result_cache import cache_stats, lookup_cached_result, store_cached_result

_MISSING_TOKENS = {"", "N/A", "NA", "[NOT SHOWN]", "NOT SHOWN", "NOT AVAILABLE", "--", "-", "NONE", "NULL"}


def _clean_str(val, default="N/A"):
    s = str(val or "").strip()
    return default if s.upper() in _MISSING_TOKENS else s


def _clean_reg(raw_reg, searched_reg=""):
    """Prefer board Reg No. when shown; fall back to user's searched Reg No. instead of [NOT SHOWN]."""
    val = str(raw_reg or "").strip()
    if val.upper() in _MISSING_TOKENS:
        s = str(searched_reg or "").strip()
        return s if s else "N/A"
    return val


def _extract_inst_and_eiin(raw_inst, raw_eiin=""):
    """Extract separate institution name and numeric EIIN without duplicates or (EIIN: N/A)."""
    inst = _clean_str(raw_inst, "N/A")
    eiin = _clean_str(raw_eiin, "N/A")
    m = re.search(r'\(?\bEIIN\s*[:#-]?\s*(\d{4,7})\)?', inst, re.IGNORECASE)
    if m:
        if eiin == "N/A":
            eiin = m.group(1)
        inst = re.sub(r'\s*\(?\bEIIN\s*[:#-]?\s*\d{4,7}\)?', '', inst, flags=re.IGNORECASE).strip(" ,;-")
    if not inst:
        inst = "N/A"
    return inst, eiin

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, 'public')
PROFILES_FILE = os.path.join(BASE_DIR, 'profiles.json')
TMP_PROFILES_FILE = '/tmp/rs_profiles.json'
SECRET_FILE = os.path.join(BASE_DIR, '.secret.key')
TMP_SECRET_FILE = '/tmp/.rs_secret.key'


def _load_secret():
    """Load or create HMAC signing key safely across writable & read-only filesystems."""
    env = os.environ.get('RS_SECRET')
    if env:
        return env.encode('utf-8')
    for path in (SECRET_FILE, TMP_SECRET_FILE):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    val = f.read().strip()
                    if val:
                        return val.encode('utf-8')
            except Exception:
                pass
    generated = secrets.token_hex(32)
    for path in (SECRET_FILE, TMP_SECRET_FILE):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(generated)
            break
        except Exception:
            continue
    return generated.encode('utf-8')


SIGN_SECRET = _load_secret()


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


HSC_SUBJECT_MAP = {
    "101": {"en": "Bangla I", "bn": "বাংলা ১ম পত্র"},
    "102": {"en": "Bangla II", "bn": "বাংলা ২য় পত্র"},
    "101-102": {"en": "Bangla", "bn": "বাংলা"},
    "107": {"en": "English I", "bn": "ইংরেজি ১ম পত্র"},
    "108": {"en": "English II", "bn": "ইংরেজি ২য় পত্র"},
    "107-108": {"en": "English", "bn": "ইংরেজি"},
    "154": {"en": "Information & Communication Technology", "bn": "তথ্য ও যোগাযোগ প্রযুক্তি"},
    "275": {"en": "Information & Communication Technology (ICT)", "bn": "তথ্য ও যোগাযোগ প্রযুক্তি"},
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
    "274": {"en": "Islamic History & Culture II", "bn": "ইসলামের ইতিহাস ও সংস্কৃতি ২য় পত্র"},
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
}

SSC_SUBJECT_MAP = {
    "101": {"en": "Bangla", "bn": "বাংলা"},
    "101-102": {"en": "Bangla", "bn": "বাংলা"},
    "107": {"en": "English", "bn": "ইংরেজি"},
    "107-108": {"en": "English", "bn": "ইংরেজি"},
    "109": {"en": "Mathematics", "bn": "গণিত"},
    "111": {"en": "Islam & Moral Education", "bn": "ইসলাম ও নৈতিক শিক্ষা"},
    "112": {"en": "Hindu Religion & Moral Education", "bn": "হিন্দুধর্ম ও নৈতিক শিক্ষা"},
    "113": {"en": "Christian Religion & Moral Education", "bn": "খ্রিষ্টধর্ম ও নৈতিক শিক্ষা"},
    "114": {"en": "Buddhist Religion & Moral Education", "bn": "বৌদ্ধধর্ম ও নৈতিক শিক্ষা"},
    "126": {"en": "Higher Mathematics", "bn": "উচ্চতর গণিত"},
    "127": {"en": "Science", "bn": "বিজ্ঞান"},
    "133": {"en": "Agriculture Studies", "bn": "কৃষিশিক্ষা"},
    "136": {"en": "Physics", "bn": "পদার্থবিজ্ঞান"},
    "137": {"en": "Chemistry", "bn": "রসায়ন"},
    "138": {"en": "Biology", "bn": "জীববিজ্ঞান"},
    "140": {"en": "Business Entrepreneurship", "bn": "ব্যবসায় উদ্যোগ"},
    "141": {"en": "Finance & Banking", "bn": "ফিন্যান্স ও ব্যাংকিং"},
    "143": {"en": "Accounting", "bn": "হিসাববিজ্ঞান"},
    "144": {"en": "Business Entrepreneurship", "bn": "ব্যবসায় উদ্যোগ"},
    "145": {"en": "Finance & Banking", "bn": "ফিন্যান্স ও ব্যাংকিং"},
    "146": {"en": "Accounting", "bn": "হিসাববিজ্ঞান"},
    "147": {"en": "Physical Education, Health Science & Sports", "bn": "শারীরিক শিক্ষা, স্বাস্থ্যবিজ্ঞান ও খেলাধুলা"},
    "150": {"en": "Bangladesh & Global Studies", "bn": "বাংলাদেশ ও বিশ্বপরিচয়"},
    "151": {"en": "Home Science", "bn": "গার্হস্থ্য বিজ্ঞান"},
    "152": {"en": "Finance & Banking", "bn": "ফিন্যান্স ও ব্যাংকিং"},
    "153": {"en": "History of Bangladesh & World Civilization", "bn": "বাংলাদেশের ইতিহাস ও বিশ্বসভ্যতা"},
    "154": {"en": "Information & Communication Technology", "bn": "তথ্য ও যোগাযোগ প্রযুক্তি"},
    "156": {"en": "Career Education", "bn": "ক্যারিয়ার শিক্ষা"},
    "110": {"en": "Geography & Environment", "bn": "ভূগোল ও পরিবেশ"},
    "141-142": {"en": "Economics", "bn": "অর্থনীতি"},
}

GRADE_POINT_MAP = {
    "A+": "5.00", "A": "4.00", "A-": "3.50",
    "B": "3.00", "C": "2.00", "D": "1.00", "F": "0.00",
}


def resolve_subject(code, exam="HSC", sub_map=None, fallback_name=""):
    """Resolve subject code cleanly across SSC, HSC, and API sub_details."""
    exam_u = str(exam or "HSC").upper()
    code_s = str(code or "").strip()
    base = code_s.split('-')[0].split('+')[0].strip()

    api_en = ""
    if sub_map:
        api_en = sub_map.get(code_s) or sub_map.get(base) or ""

    primary = SSC_SUBJECT_MAP if exam_u == "SSC" else HSC_SUBJECT_MAP
    secondary = HSC_SUBJECT_MAP if exam_u == "SSC" else SSC_SUBJECT_MAP
    info = primary.get(code_s) or primary.get(base) or secondary.get(code_s) or secondary.get(base)

    if info:
        return {"en": api_en.title() if api_en else info["en"], "bn": info["bn"]}
    en_txt = api_en.title() if api_en else (fallback_name or f"Subject {code_s}")
    return {"en": en_txt, "bn": fallback_name or en_txt}


def sign_result(d):
    """Create a tamper-proof HMAC-SHA256 token from an official board result."""
    exam_u = str(d.get('exam', 'HSC')).upper()
    subs_parts = []
    for s in d.get('subjects', []):
        code = str(s.get('code', '')).replace(':', '').replace(';', '')
        grade = str(s.get('grade', '')).replace(':', '').replace(';', '')
        marks = str(s.get('total', s.get('marks', '--'))).replace(':', '').replace(';', '')
        known = (exam_u == 'SSC' and code in SSC_SUBJECT_MAP) or (code in HSC_SUBJECT_MAP)
        extra_nm = '' if known else str(s.get('name_en', '')).replace(':', ' ').replace(';', ' ')[:40]
        subs_parts.append(f"{code}:{grade}:{marks}:{extra_nm}" if extra_nm else f"{code}:{grade}:{marks}")
    payload = {
        'n': d.get('name', ''), 'f': d.get('father', ''), 'm': d.get('mother', ''),
        'r': str(d.get('roll', '')), 'g': str(d.get('reg', '')), 'b': d.get('board', ''),
        'e': exam_u, 'y': str(d.get('year', '')), 'p': str(d.get('gpa', '')),
        'gr': d.get('group', ''), 'ss': str(d.get('session', '')),
        'tp': str(d.get('type', 'REGULAR')),
        'i': d.get('college', ''), 'ei': str(d.get('eiin', '')),
        's': ';'.join(subs_parts), 't': int(time.time()),
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


def verify_token_payload(token):
    token = (token or '').strip()
    raw = verify_token(token) if token else None
    if not raw:
        return {"valid": False, "error": "Invalid or tampered marksheet token."}

    exam_u = raw.get('e', 'HSC')
    subs = []
    if raw.get('s'):
        for item in raw['s'].split(';'):
            if not item:
                continue
            parts = item.split(':')
            code = parts[0] if len(parts) > 0 else ''
            grade = parts[1] if len(parts) > 1 else ''
            marks = parts[2] if len(parts) > 2 else ''
            extra_nm = parts[3] if len(parts) > 3 else ''
            sub_meta = resolve_subject(code, exam_u, None, extra_nm)
            subs.append({
                'code': code,
                'name_en': sub_meta.get('en', f'Subject {code}'),
                'name_bn': sub_meta.get('bn', f'বিষয় {code}'),
                'grade': grade,
                'gp': GRADE_POINT_MAP.get(grade.upper(), '--'),
                'marks': marks,
                'total': marks,
            })

    doc_id = 'RS-' + hashlib.sha256(token.encode()).hexdigest()[:10].upper()
    return {
        "valid": True,
        "data": {
            'doc_id': doc_id, 'name': raw.get('n', ''), 'father': raw.get('f', ''),
            'mother': raw.get('m', ''), 'roll': raw.get('r', ''), 'reg': raw.get('g', ''),
            'board': raw.get('b', ''), 'exam': exam_u, 'year': raw.get('y', ''),
            'gpa': raw.get('p', ''), 'group': raw.get('gr', ''),
            'session': raw.get('ss', 'N/A'), 'type': raw.get('tp', 'REGULAR'),
            'college': raw.get('i', ''), 'eiin': raw.get('ei', ''),
            'subjects': subs, 'issued_at': raw.get('t', 0), 'token': token,
        },
    }


def _format_parts(p_list):
    if not p_list:
        return "--", "--"
    if len(p_list) == 1:
        return p_list[0], p_list[0]
    try:
        return " + ".join(p_list), str(sum(int(x) for x in p_list))
    except ValueError:
        return " + ".join(p_list), "--"


def parse_subjects(display_details, sub_details=None, exam="HSC"):
    subjects = []
    if not display_details:
        return subjects

    sub_map = {}
    if isinstance(sub_details, list):
        for s in sub_details:
            if isinstance(s, dict):
                c = str(s.get("SUB_CODE") or s.get("sub_code") or "").strip()
                n = str(s.get("SUB_NAME") or s.get("sub_name") or "").strip()
                if c and n:
                    sub_map[c] = n

    items = [x.strip() for x in display_details.split(',') if x.strip()] if isinstance(display_details, str) else list(display_details)

    for item in items:
        if isinstance(item, list) and len(item) >= 3:
            code = str(item[0]).strip()
            grade = str(item[2]).strip().upper()
            total_marks = str(item[3]).strip() if len(item) > 3 else "--"
            sub_info = resolve_subject(code, exam, sub_map)
            subjects.append({
                "code": code, "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'], "name_en": sub_info['en'],
                "cq": "--", "cq_total": "--", "mcq": "--", "mcq_total": "--",
                "practical": "--", "practical_total": "--",
                "total": total_marks or "--", "marks": total_marks or "--",
                "grade": grade, "gp": GRADE_POINT_MAP.get(grade, "--"), "papers": [],
            })
            continue

        item_str = str(item).strip()
        m_edu = re.match(r'^([\d\-]+)\s+([A-F][\+\-]?)\s+([\s\S]*?)(?:\s+(\d+))?$', item_str)
        if m_edu:
            code = m_edu.group(1).strip()
            grade = m_edu.group(2).strip().upper()
            raw_name = m_edu.group(3).strip().title()
            total_marks = str(int(m_edu.group(4).strip())) if (m_edu.group(4) and grade != 'F') else "--"
            sub_info = resolve_subject(code, exam, sub_map, raw_name)
            subjects.append({
                "code": code, "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'], "name_en": sub_info['en'],
                "cq": "--", "cq_total": "--", "mcq": "--", "mcq_total": "--",
                "practical": "--", "practical_total": "--",
                "total": total_marks, "marks": total_marks,
                "grade": grade, "gp": GRADE_POINT_MAP.get(grade, "--"), "papers": [],
            })
            continue

        code, grade, total_marks = "", "", "--"
        cq = cq_total = mcq = mcq_total = practical = practical_total = "--"
        paper_details = []

        if ':' in item_str:
            left, right = item_str.split(':', 1)
            left, right = left.strip(), right.strip()
            if '=' in right:
                r_parts = right.split('=')
                grade = r_parts[-1].strip()
                if r_parts[0].strip().isdigit():
                    total_marks = str(int(r_parts[0].strip()))
                code = left
            else:
                grade = right

            if '=' in left:
                l_parts = left.split('=')
                code = l_parts[0].strip()
                if len(l_parts) > 2:
                    total_marks = l_parts[2].strip()
                    for p_idx, paper in enumerate(l_parts[1].strip().split('-')):
                        parts = paper.split('+')
                        paper_details.append({
                            "paper": p_idx + 1,
                            "cq": parts[0].strip() if len(parts) > 0 else "",
                            "practical": parts[1].strip() if len(parts) > 1 else "",
                            "mcq": parts[2].strip() if len(parts) > 2 else "",
                        })
                    cq, cq_total = _format_parts([p['cq'] for p in paper_details if p['cq']])
                    practical, practical_total = _format_parts([p['practical'] for p in paper_details if p['practical'] and p['practical'] != '0'])
                    mcq, mcq_total = _format_parts([p['mcq'] for p in paper_details if p['mcq']])
                elif len(l_parts) == 2 and l_parts[1].strip().isdigit():
                    total_marks = str(int(l_parts[1].strip()))
            else:
                code = left

            if '=' in grade:
                g_parts = grade.split('=')
                grade = g_parts[-1].strip()
                if total_marks == "--" and g_parts[0].strip().isdigit():
                    total_marks = str(int(g_parts[0].strip()))

            grade_u = grade.upper()
            sub_info = resolve_subject(code, exam, sub_map)
            subjects.append({
                "code": code, "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'], "name_en": sub_info['en'],
                "cq": cq, "cq_total": cq_total, "mcq": mcq, "mcq_total": mcq_total,
                "practical": practical, "practical_total": practical_total,
                "total": total_marks or "--", "marks": total_marks or "--",
                "grade": grade_u, "gp": GRADE_POINT_MAP.get(grade_u, "--"), "papers": paper_details,
            })
        elif '=' in item_str:
            eqs = item_str.split('=')
            code = eqs[0].strip()
            grade_u = eqs[-1].strip().upper()
            if len(eqs) > 2 and eqs[1].strip().isdigit():
                total_marks = str(int(eqs[1].strip()))
            sub_info = resolve_subject(code, exam, sub_map)
            subjects.append({
                "code": code, "name": f"{sub_info['bn']} ({sub_info['en']})",
                "name_bn": sub_info['bn'], "name_en": sub_info['en'],
                "cq": cq, "cq_total": cq_total, "mcq": mcq, "mcq_total": mcq_total,
                "practical": practical, "practical_total": practical_total,
                "total": total_marks or "--", "marks": total_marks or "--",
                "grade": grade_u, "gp": GRADE_POINT_MAP.get(grade_u, "--"), "papers": [],
            })

    return subjects


def check_cache_sync(data):
    """Look up a previously fetched result in the 1-year server/Blob cache using Roll + Reg."""
    board = str(data.get("board", "rajshahi")).strip().lower()
    exam = str(data.get("exam", "hsc")).strip().lower()
    year = str(data.get("year", "2026")).strip()
    roll = str(data.get("roll", "")).strip()
    reg = str(data.get("reg", "")).strip()
    pref = str(data.get("engine", "")).strip().lower() or None

    if not roll or not reg:
        return {"success": False, "cache_hit": False, "error": "Roll and Registration No. are required for 1-Year Fast Cache lookup."}, 400

    cached = lookup_cached_result(exam, year, board, roll, reg, preferred_engine=pref)
    if not cached:
        return {"success": False, "cache_hit": False, "error": "Not yet in 1-Year Server Cache — solve the security key once to fetch & cache it."}, 200

    cached["reg"] = _clean_reg(cached.get("reg"), reg)
    attach_verification(cached)
    return {"success": True, "cache_hit": True, "data": cached}, 200


def check_eduboard_sync(data):
    board = str(data.get("board", "dhaka")).strip().lower()
    exam_val = str(data.get("exam", "hsc")).upper()
    year = str(data.get("year", "2026")).strip()
    roll = str(data.get("roll", "")).strip()
    reg = str(data.get("reg", "")).strip()
    captcha = str(data.get("captcha", "")).strip()
    hash_val = data.get("hash", "")
    timestamp = data.get("timestamp", 0)
    force_refresh = bool(data.get("force_refresh", False))

    if not roll or not reg:
        return {"success": False, "error": "Roll and Registration number are required."}, 400

    if not force_refresh:
        cached = lookup_cached_result(exam_val.lower(), year, board, roll, reg, preferred_engine="eduboard")
        if cached:
            cached["reg"] = _clean_reg(cached.get("reg"), reg)
            attach_verification(cached)
            return {"success": True, "cache_hit": True, "data": cached}, 200

    if not captcha:
        return {"success": False, "error": "Roll, Registration number, and Security Code are required."}, 400

    res = eduboard_client.get_result(board, year, roll, reg, captcha, hash_val, timestamp)
    if res.get("success"):
        sd = res["data"]
        inst, eiin = _extract_inst_and_eiin(sd.get("college"), sd.get("eiin"))
        sd["college"] = inst
        sd["eiin"] = eiin
        sd["reg"] = _clean_reg(sd.get("reg"), reg)
        sd["session"] = _clean_str(sd.get("session"), "N/A")
        sd["type"] = _clean_str(sd.get("type"), "REGULAR")
        sd["subjects"] = parse_subjects(sd.get("raw_result_str", ""), exam=exam_val)
        sd["source"] = "eduboardresults.gov.bd"
        sd["exam"] = exam_val
        sd.pop("raw_result_str", None)
        store_cached_result("eduboard", exam_val.lower(), year, board, roll, sd["reg"], sd)
        attach_verification(sd)
        return {"success": True, "cache_hit": False, "data": sd}, 200
    return {"success": False, "error": res.get("error", "Result not found or invalid captcha code.")}, 200


def check_eboard_sync(data):
    session_id = str(data.get("session_id", "")).strip()
    board = str(data.get("board", "rajshahi")).strip().lower()
    exam = str(data.get("exam", "hsc")).strip().lower()
    year = str(data.get("year", "2026")).strip()
    roll = str(data.get("roll", "")).strip()
    reg = str(data.get("reg", "")).strip()
    captcha = str(data.get("captcha", "")).strip()
    force_refresh = bool(data.get("force_refresh", False))

    if not roll:
        return {"success": False, "error": "Roll number is required."}, 400

    if not force_refresh and reg:
        cached = lookup_cached_result(exam, year, board, roll, reg, preferred_engine="eboard")
        if cached:
            cached["reg"] = _clean_reg(cached.get("reg"), reg)
            attach_verification(cached)
            return {"success": True, "cache_hit": True, "data": cached}, 200

    if not session_id or not captcha:
        return {"success": False, "error": "Roll, Security Key and Captcha Session are required."}, 400

    res = eboard_client.get_result(session_id, board, exam, year, roll, reg, captcha)
    if res.get("success"):
        raw = res["data"]
        details = raw.get("display_details") or raw.get("log_display_details") or ""
        subjects = parse_subjects(details, sub_details=raw.get("sub_details") or [], exam=exam.upper())

        res_det = str(raw.get("res_detail", "") or "")
        raw_gpa = str(raw.get("gpa", "") or "")
        if not raw_gpa and "GPA=" in res_det:
            raw_gpa = res_det.replace("GPA=", "").strip("[] ")
        elif not raw_gpa:
            raw_gpa = "PASSED" if res_det == "P" else (res_det or "N/A")

        inst, eiin = _extract_inst_and_eiin(raw.get("inst_name"), raw.get("eiin"))
        clean_reg = _clean_reg(raw.get("regno"), reg)
        normalized = {
            "source": "result.bangladeshgov.org (All-Board Gateway)",
            "name": _clean_str(raw.get("name"), "N/A"),
            "father": _clean_str(raw.get("fname"), "N/A"),
            "mother": _clean_str(raw.get("mname"), "N/A"),
            "roll": _clean_str(raw.get("roll_no"), roll),
            "reg": clean_reg,
            "board": _clean_str(raw.get("board_name"), board.capitalize()),
            "exam": exam.upper(),
            "year": str(year),
            "gpa": raw_gpa,
            "status": "F" if ("FAIL" in res_det.upper() or raw_gpa in ("F", "0.00")) else "P",
            "session": _clean_str(raw.get("session"), "N/A"),
            "type": _clean_str(raw.get("stud_type") or raw.get("type"), "REGULAR"),
            "college": inst,
            "eiin": eiin,
            "group": _clean_str(raw.get("stud_group"), "N/A"),
            "subjects": subjects,
        }
        if reg:
            store_cached_result("eboard", exam, year, board, roll, reg, normalized)
        attach_verification(normalized)
        return {"success": True, "cache_hit": False, "data": normalized}, 200
    return {"success": False, "error": res.get("error", "Result not found or incorrect security key.")}, 200


def check_ebr_sync(data):
    board = str(data.get("board", "rajshahi")).strip().lower()
    exam = str(data.get("exam", "hsc")).strip().lower()
    year = str(data.get("year", "2026")).strip()
    roll = str(data.get("roll", "")).strip()
    reg = str(data.get("reg", "")).strip()
    cf_token = str(data.get("cf_turnstile_response", "")).strip()

    if not roll:
        return {"success": False, "error": "Roll number is required."}, 400

    qs = urllib.parse.urlencode({
        'exam': exam, 'year': year, 'board': board, 'roll': roll, 'reg': reg,
        'cf-turnstile-response': cf_token,
    })
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': 'application/json', 'Referer': 'https://ebr.bd/', 'Origin': 'https://ebr.bd',
    }
    if cf_token:
        headers['cf-turnstile-response'] = cf_token

    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(f"https://api.ebr.bd/?{qs}", headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            res_json = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        try:
            res_json = json.loads(e.read().decode('utf-8'))
        except Exception:
            res_json = {"error": f"HTTP {e.code}"}
    except Exception as e:
        res_json = {"error": str(e)}

    if res_json.get("success") and res_json.get("data", {}).get("result"):
        res_obj = res_json["data"]["result"]
        info = res_obj.get("info", {})
        subs = parse_subjects(res_obj.get("result", ""), exam=exam.upper())
        student_data = {
            "name": info.get("name", "N/A"),
            "father": info.get("fatherName", "N/A"),
            "mother": info.get("motherName", "N/A"),
            "roll": info.get("rollNo", roll),
            "reg": info.get("regNo", reg),
            "board": board, "exam": exam.upper(),
            "year": info.get("passYear", year),
            "gpa": str(info.get("gpa", "")) or ("PASSED" if info.get("result") == "P" else info.get("result", "FAILED")),
            "group": info.get("groupName", "N/A"),
            "college": info.get("instituteName", "N/A"),
            "eiin": info.get("eiin", ""),
            "subjects": subs,
            "source": "api.ebr.bd",
            "merit": {
                "board_merit": info.get("boardMerit"),
                "group_merit": info.get("groupMerit"),
                "institute_merit": info.get("eiinMerit"),
                "total_marks": info.get("totalMarks"),
                "board_merit_w4": info.get("boardMeritW4"),
                "group_merit_w4": info.get("groupMeritW4"),
                "institute_merit_w4": info.get("eiinMeritW4"),
                "total_marks_w4": info.get("totalMarksWithoutFourth"),
            },
        }
        attach_verification(student_data)
        return {"success": True, "data": student_data}, 200

    msg = res_json.get("msg") or res_json.get("message") or res_json.get("error") or "Access Denied: Missing CAPTCHA Token"
    return {
        "success": False,
        "requires_turnstile": True,
        "requires_fallback": True,
        "error": (
            f"ebr.bd leaderboard API enforces Cloudflare Turnstile on ebr.bd origin ({msg}). "
            "Switching to All-Board / Full Marks engines which work natively here."
        ),
    }, 200


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

    m = re.search(rf'{re.escape(target_roll)}(?:\\133|\[)([\d\.]+)(?:\\135|\])', combined)
    if m:
        return {"found": True, "roll": target_roll, "gpa": m.group(1), "institution": institution, "eiin": eiin}

    mf = re.search(rf'{re.escape(target_roll)}(?:\\133|\[)([^\]\\]+)(?:\\135|\])', combined)
    if mf:
        return {"found": True, "roll": target_roll, "gpa": "FAIL", "detail": mf.group(1), "institution": institution, "eiin": eiin}

    return {"found": False, "institution": institution, "eiin": eiin}


def _active_profiles_path():
    if os.path.exists(TMP_PROFILES_FILE):
        return TMP_PROFILES_FILE
    if os.path.exists(PROFILES_FILE):
        return PROFILES_FILE
    return PROFILES_FILE


def read_profiles():
    p = _active_profiles_path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def write_profiles(profiles):
    for p in (PROFILES_FILE, TMP_PROFILES_FILE):
        try:
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(profiles, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            continue
    return False
