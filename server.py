import asyncio
import os
import re
import sys
import time
import urllib3
import requests
from aiohttp import web

from core import (
    BASE_DIR,
    GRADE_POINT_MAP,
    HSC_SUBJECT_MAP,
    PUBLIC_DIR,
    SIGN_SECRET,
    SSC_SUBJECT_MAP,
    attach_verification,
    cache_stats,
    check_cache_sync,
    check_eboard_sync,
    check_ebr_sync,
    check_eduboard_sync,
    parse_pdf_for_roll_sync,
    parse_subjects,
    read_profiles,
    resolve_subject,
    sign_result,
    verify_token,
    verify_token_payload,
    write_profiles,
)
from eboard_client import eboard_client
from eduboard_client import eduboard_client

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global Sniper state
sniper_state = {
    "status": "IDLE",
    "params": None,
    "attempts": 0,
    "start_time": None,
    "last_attempt_time": None,
    "last_status": "Idle",
    "result": None,
    "logs": [],
}
sniper_task = None


def add_sniper_log(msg):
    t_str = time.strftime('%H:%M:%S')
    sniper_state["logs"].append(f"[{t_str}] {msg}")
    if len(sniper_state["logs"]) > 100:
        sniper_state["logs"].pop(0)


# ----------------- eduboardresults.gov.bd Handlers -----------------
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
        loop = asyncio.get_event_loop()
        payload, status = await loop.run_in_executor(None, check_eduboard_sync, data)
        return web.json_response(payload, status=status)
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


async def ebr_check_endpoint(request):
    try:
        data = await request.json()
        loop = asyncio.get_event_loop()
        payload, status = await loop.run_in_executor(None, check_ebr_sync, data)
        return web.json_response(payload, status=status)
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


async def cache_check_endpoint(request):
    try:
        data = await request.json()
        loop = asyncio.get_event_loop()
        payload, status = await loop.run_in_executor(None, check_cache_sync, data)
        return web.json_response(payload, status=status)
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


# ----------------- All-Board / EBR Mirror Handlers -----------------
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
        loop = asyncio.get_event_loop()
        payload, status = await loop.run_in_executor(None, check_eboard_sync, data)
        return web.json_response(payload, status=status)
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


# ----------------- Legacy /api/check Unified Guidance -----------------
async def check_result_endpoint(request):
    return web.json_response({
        "success": False,
        "needs_eboard": True,
        "error": "Please select Full Marks (eduboard) or All-Board (result.bangladeshgov.org) and enter the visible Security Key.",
    })


# ----------------- Auto-Retry Monitor (Server-Busy Retry) -----------------
async def sniper_worker():
    global sniper_state
    params = sniper_state["params"]
    engine = params.get("engine", "eboard")
    board = params.get("board", "rajshahi").lower()
    exam = params.get("exam", "hsc")
    year = params.get("year", "2026")
    roll = params["roll"]
    interval = max(3, params.get("interval", 5))

    add_sniper_log(f"Monitor started [{engine.upper()}] — Roll: {roll}, Board: {board.capitalize()}, Exam: {exam.upper()}-{year}")
    loop = asyncio.get_event_loop()

    while sniper_state["status"] == "RUNNING":
        sniper_state["attempts"] += 1
        sniper_state["last_attempt_time"] = time.strftime('%H:%M:%S')
        try:
            if engine == 'eduboard':
                res, _ = await loop.run_in_executor(None, check_eduboard_sync, params)
            else:
                res, _ = await loop.run_in_executor(None, check_eboard_sync, params)

            if res.get("success") and res.get("data"):
                sniper_state["status"] = "FOUND"
                sniper_state["result"] = res["data"]
                sniper_state["last_status"] = "Result Captured!"
                add_sniper_log(f"RESULT CAPTURED! Name: {res['data'].get('name')} | GPA: {res['data'].get('gpa')}")
                break

            err = str(res.get("error", ""))
            if any(k in err.lower() for k in ("captcha", "security key", "expired", "ক্যাপচা")):
                sniper_state["status"] = "CAPTCHA_ERROR"
                sniper_state["last_status"] = "Security Key expired/invalid — enter new key"
                add_sniper_log(f"Attempt #{sniper_state['attempts']}: {err}")
                break

            sniper_state["last_status"] = f"Retrying in {interval}s ({err[:50]})"
            add_sniper_log(f"Attempt #{sniper_state['attempts']}: {err}")
        except Exception as e:
            sniper_state["last_status"] = f"Network Busy — retrying in {interval}s"
            add_sniper_log(f"Attempt #{sniper_state['attempts']} Server Busy: {str(e)}")

        await asyncio.sleep(interval)


async def sniper_start_endpoint(request):
    global sniper_state, sniper_task
    data = await request.json()
    roll = str(data.get("roll", "")).strip()
    captcha = str(data.get("captcha", "")).strip()

    if not roll:
        return web.json_response({"success": False, "error": "Roll number is required."}, status=400)
    if not captcha:
        return web.json_response({"success": False, "error": "Please solve the visible Security Key before starting."}, status=400)

    if sniper_task and not sniper_task.done():
        sniper_state["status"] = "STOPPED"
        sniper_task.cancel()

    sniper_state = {
        "status": "RUNNING",
        "params": {
            "engine": str(data.get("engine", "eboard")).strip().lower(),
            "roll": roll,
            "reg": str(data.get("reg", "")).strip(),
            "board": str(data.get("board", "rajshahi")).strip().lower(),
            "exam": str(data.get("exam", "hsc")).strip(),
            "year": str(data.get("year", "2026")).strip(),
            "captcha": captcha,
            "session_id": str(data.get("session_id", "")).strip(),
            "hash": data.get("hash", ""),
            "timestamp": data.get("timestamp", 0),
            "interval": int(data.get("interval", 5)),
        },
        "attempts": 0,
        "start_time": time.strftime('%H:%M:%S'),
        "last_attempt_time": None,
        "last_status": "Starting monitor loop...",
        "result": None,
        "logs": [],
    }

    sniper_task = asyncio.create_task(sniper_worker())
    return web.json_response({"success": True, "message": "Auto-retry monitor initiated."})


async def sniper_stop_endpoint(request):
    global sniper_state, sniper_task
    if sniper_task and not sniper_task.done():
        sniper_state["status"] = "STOPPED"
        sniper_task.cancel()
        add_sniper_log("Monitor stopped by user.")
    return web.json_response({"success": True, "message": "Monitor stopped."})


async def sniper_status_endpoint(request):
    return web.json_response({
        "status": sniper_state["status"],
        "attempts": sniper_state["attempts"],
        "start_time": sniper_state["start_time"],
        "last_attempt_time": sniper_state["last_attempt_time"],
        "last_status": sniper_state["last_status"],
        "result": sniper_state["result"],
        "logs": sniper_state["logs"][-30:],
    })


# ----------------- PDF Search -----------------
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
            return web.json_response({"success": False, "error": "Roll number is required."}, status=400)
        if not pdf_bytes or len(pdf_bytes) < 100:
            return web.json_response({"success": False, "error": "Please upload a valid result PDF file."}, status=400)

        loop = asyncio.get_event_loop()
        res = await loop.run_in_executor(None, parse_pdf_for_roll_sync, pdf_bytes, target_roll)
        return web.json_response({"success": True, "data": res})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


# ----------------- Profiles -----------------
async def get_profiles_endpoint(request):
    return web.json_response({"success": True, "profiles": read_profiles()})


async def save_profile_endpoint(request):
    try:
        new_profile = await request.json()
        new_profile["id"] = f"p_{int(time.time() * 1000)}"
        profiles = read_profiles()
        profiles.append(new_profile)
        write_profiles(profiles)
        return web.json_response({"success": True, "profile": new_profile})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


async def delete_profile_endpoint(request):
    try:
        prof_id = request.match_info.get('id', '')
        profiles = [p for p in read_profiles() if p.get('id') != prof_id]
        write_profiles(profiles)
        return web.json_response({"success": True})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


# ----------------- Verification & Static Pages -----------------
NO_CACHE = {
    'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'Expires': '0',
}


async def index_handler(request):
    return web.FileResponse(os.path.join(PUBLIC_DIR, 'index.html'), headers=NO_CACHE)


async def verify_api_endpoint(request):
    return web.json_response(verify_token_payload(request.query.get('t', '')))


async def health_endpoint(request):
    return web.json_response({"status": "ok", "service": "ResultSniper BD", "timestamp": int(time.time()), "cache": cache_stats()})


PAGE_MAP = {
    'about': 'about.html',
    'terms': 'terms.html',
    'privacy': 'privacy.html',
    'privacy-policy': 'privacy.html',
    'verify': 'verify.html',
}
ROOT_FILES = {
    'llms.txt', 'robots.txt', 'sitemap.xml', 'favicon.svg', 'favicon.ico',
    'site.webmanifest', 'humans.txt', 'about.html', 'terms.html', 'privacy.html', 'verify.html',
}


async def page_handler(request):
    name = request.match_info.get('name', '').strip('/').lower()
    fname = PAGE_MAP.get(name) or (name if name in ROOT_FILES else None)
    if not fname:
        raise web.HTTPNotFound(text="404 - Page not found")
    path = os.path.join(PUBLIC_DIR, 'favicon.svg' if fname == 'favicon.ico' else fname)
    if not os.path.exists(path):
        raise web.HTTPNotFound(text="404 - Page not found")
    if fname in ('robots.txt', 'sitemap.xml'):
        proto = request.headers.get('X-Forwarded-Proto', request.scheme)
        origin = f"{proto}://{request.host}"
        with open(path, 'r', encoding='utf-8') as f:
            body = (
                f.read()
                .replace('https://resultsniper-bd.vercel.app', origin)
                .replace('https://resultsniper-bd.local', origin)
            )
        return web.Response(
            text=body,
            content_type='application/xml' if fname.endswith('.xml') else 'text/plain',
            charset='utf-8',
        )
    headers = dict(NO_CACHE) if fname.endswith('.html') else {}
    if fname.endswith('.txt'):
        headers['Content-Type'] = 'text/plain; charset=utf-8'
    return web.FileResponse(path, headers=headers)


def create_app():
    app = web.Application(client_max_size=50 * 1024 * 1024)
    app.router.add_get('/', index_handler)
    app.router.add_get('/health', health_endpoint)
    app.router.add_get('/api/verify', verify_api_endpoint)
    app.router.add_post('/api/check', check_result_endpoint)
    app.router.add_post('/api/ebr/check', ebr_check_endpoint)
    app.router.add_post('/api/cache/check', cache_check_endpoint)
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
    print("=======================================================")
    print(f"ResultSniper BD is running at: http://localhost:{port}")
    print("=======================================================")
    web.run_app(create_app(), host='0.0.0.0', port=port)
