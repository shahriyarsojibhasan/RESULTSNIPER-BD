# 🎯 ResultSniper BD

<p align="center">
  <img src="public/favicon.svg" width="90" height="90" alt="ResultSniper BD Logo" />
</p>

<h3 align="center"><strong>ResultSniper BD — Bangladesh Board Results, Merit Analytics &amp; 1-Page QR Verified Marksheet Platform</strong></h3>

<p align="center">
  <strong>Lead Developer:</strong> <a href="https://github.com/shahriyarsojibhasan">Shahriyar Sojib Hasan</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue.svg" alt="Python 3" />
  <img src="https://img.shields.io/badge/Aiohttp-Async%20Engine-brightgreen.svg" alt="Aiohttp" />
  <img src="https://img.shields.io/badge/Security-HMAC--SHA256-red.svg" alt="Security" />
  <img src="https://img.shields.io/badge/Language-English%20%2B%20Bangla-teal.svg" alt="EN + BN" />
  <img src="https://img.shields.io/badge/Developer-Shahriyar%20Sojib%20Hasan-emerald.svg" alt="Developer" />
</p>

---

## 📖 Overview

**ResultSniper BD** is a resilient, bilingual (**English default + বাংলা switcher**) Education Board Result extraction, merit score calculator, and cryptographically verified marksheet platform for Bangladesh **HSC, SSC, JSC, DIBS, Madrasah, and Technical** examinations.

Developed & maintained by **Shahriyar Sojib Hasan**.

---

## ✨ Key Features

### 1. ⚡ Multi-Engine Official API Architecture
- **Engine 1: `eduboardresults.gov.bd` (Official Detailed Marks)**
  - Fetches subject-wise numeric marks alongside candidate profile, GPA, and transcript breakdown.
- **Engine 2: `result.bangladeshgov.org` (All-Board / EBR Mirror Gateway)**
  - Covers all 11 Education Boards (`Dhaka`, `Rajshahi`, `Cumilla`, `Chattogram`, `Barishal`, `Sylhet`, `Jashore`, `Dinajpur`, `Mymensingh`, `Madrasah`, `Technical`) across SSC, HSC, JSC, and DIBS (`2015–2026`) with subject name resolution (`sub_details`).
- **Engine 3: `api.ebr.bd` (Honest Turnstile Check & Direct Helper)**
  - Queries `api.ebr.bd` when allowed; transparently detects `ebr.bd`'s Cloudflare Turnstile domain protection (`HTTP 403`) and provides instant 1-click Roll/Reg copy + new-tab lookup without iframes.

### 2. 🛡️ Light Security Wave Banknote PDF & 1-Page Verification (`/verify`)
- **Soft Pastel Security Waves:** Subtle light emerald & champagne-gold guilloche curves, delicate corner rosettes, and microtext borders that keep text crystal-clear in print and PDF.
- **1-Page A4 & US Letter Support:** Both the main marksheet and the `/verify` certificate fit cleanly onto a **single A4 or Letter page**.
- **Official Transparent Crests:** Includes official transparent RGBA PNG crest from `app.rajshahiboard.gov.bd` for Rajshahi Board plus official emblems for every Bangladesh board.

### 3. 🔐 Cryptographic QR Verification (`HMAC-SHA256`)
- Every generated marksheet embeds a compressed payload signed via HMAC-SHA256 and a unique Document ID (`RS-XXXXXXXXXX`).
- Scanning the QR opens `/verify?t=...` — any alteration to marks, grades, roll, or name fails HMAC validation immediately.

### 4. 📊 Merit Analytics, Auto-Retry Monitor & 0.01s PDF Scanner
- Calculates Total Marks (with & without 4th subject) and Core Percentage automatically.
- **Auto-Retry Monitor:** Retries transient server-busy errors on Result Day using a valid human captcha session.
- **EIIN PDF Scanner:** Extracts student GPA and pass status from uploaded institution result PDFs in milliseconds.

---

## 🚀 24/7 Cloud Hosting (Why Render/Railway/Koyeb instead of GitHub Pages?)

> **Important:** **GitHub Pages** hosts static files (`.html`, `.js`, `.css`) only — it **cannot execute Python (`server.py`)** or backend API proxies (`/api/...`, `/api/verify`).
> To keep ResultSniper BD live **24/7**, deploy the repository to a Python/Docker cloud platform:

### Option A: One-Click Deploy on Render (Free 24/7 Ready)
1. Push this repo to GitHub (already done!).
2. Go to [render.com](https://render.com) → **New** → **Blueprint** (or **Web Service**) → Connect `ResultSniper-BD`.
3. Render automatically reads **`render.yaml`**, installs `requirements.txt`, sets `RS_SECRET`, and runs `python server.py` with `/health` monitoring.
4. *(Tip)* Pair with a free uptime monitor (e.g., UptimeRobot pinging `https://your-app.onrender.com/health` every 5–10 minutes) to prevent free-tier cold sleeps.

### Option B: Railway / Koyeb / Fly.io / Docker
- Included **`Dockerfile`** and **`Procfile`** work out-of-the-box on Railway, Koyeb, Fly.io, DigitalOcean App Platform, or any VPS (`docker build -t resultsniper . && docker run -p 8080:8080 resultsniper`).

---

## 💻 Local Run

```bash
pip install -r requirements.txt
python server.py
# Or on Windows: double-click start_app.bat
```

Open 👉 **http://localhost:8080**

---

## 🌐 Routes & SEO

| Endpoint | Purpose |
|---|---|
| `GET /` | Main Bilingual Portal (`EN` default + `বাংলা` toggle) |
| `GET /verify?t={token}` | Public Verification Portal + 1-Page A4/Letter Certificate |
| `GET /api/verify?t={token}` | JSON Cryptographic Verification Endpoint |
| `GET /health` | 24/7 Cloud Uptime Health Check |
| `GET /sitemap.xml` & `GET /robots.txt` | Dynamic domain-aware SEO sitemap & crawler rules |
| `GET /about`, `/terms`, `/privacy`, `/llms.txt` | Attribution, Legal, Privacy & LLM context |

---

## 👨‍💻 Developer

**Shahriyar Sojib Hasan**  
GitHub: [@shahriyarsojibhasan](https://github.com/shahriyarsojibhasan)
