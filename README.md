
# Incident Logger

[![CI](https://github.com/Andr3a28/incident-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/Andr3a28/incident-logger/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[![Made with Flask](https://img.shields.io/badge/Made%20with-Flask-blue)](https://flask.palletsprojects.com/)

A role-based incident logging and review system built with **Flask + SQLAlchemy**. Supports granular privileges (e.g., `can_route`, `can_reviewer`, `can_view_settings`, `can_view_audit`), reviewer mapping, alerting for GM/SDM/IM, password policy enforcement, health checks, backup & restore, and an audit trail.

---

## ✨ Highlights
- **Role-based workflow**: map logger roles to reviewer roles; reassign reviewers.
- **Alerts**: split counts by category (e.g., governance vs. delete requests).
- **Security**: password policy UI, hardened SECRET_KEY handling, CSP cleanup.
- **Ops**: `/admin/health` endpoint, optional scheduler, admin-only backups.
- **UI/UX**: top-right profile dropdown, enlarged tabs, active/hover states.

> This repo contains a clean scaffold and CI to showcase the project. Drop your production `app.py` and templates into the structure below and push.

---

## 📁 Project Structure
```
incident-logger/
├─ app/                      # your Flask app lives here
│  ├─ __init__.py
│  ├─ app.py                 # place your main Flask file here
│  ├─ templates/             # Jinja2 templates
│  ├─ static/                # CSS/JS assets
│  └─ utils/                 # helpers, tasks, schedulers
├─ tests/                    # pytest tests
│  └─ test_sanity.py
├─ .github/workflows/ci.yml  # lint + tests on push
├─ requirements.txt
├─ .gitignore
├─ SECURITY.md
├─ CONTRIBUTING.md
├─ CODE_OF_CONDUCT.md
├─ LICENSE
└─ README.md
```

---

## 🚀 Quick Start (Local)
```bash
# 1) Create & activate venv
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate

# 2) Install deps
pip install -r requirements.txt

# 3) Export dev env vars (set a strong key in prod)
export FLASK_APP=app/app.py
export FLASK_ENV=development
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# 4) Run
flask run
```

---

## ✅ Tests & Lint
```bash
pytest -q
flake8
```
CI (GitHub Actions) runs both on every push/pull request.

---

## 🧪 Demo Data
You can add a small SQLite seed script under `app/utils/seed.py` to create demo roles (GM, SDM, IM, Admin), privileges, and a sample incident.

---

## 🔒 Security
See **SECURITY.md** for reporting vulnerabilities. Avoid committing secrets. Use environment variables and rotate keys.

---

## 📹 Showcase (for recruiters)
- **Screenshots**: add PNGs in `docs/screenshots/` and reference them below.
- **Demo video**: upload to YouTube or attach a short MP4 in `docs/demo/`.
- **Key features**: link timestamps (routing, alerts, health, password policy).

> Example: _“2:10 – reviewer mapping; 3:25 – governance alert split; 4:05 – admin health metrics”_

---

## 📝 Resume Snippet
- Built a Flask/SQLAlchemy **Incident Logger** with role-based routing, granular privileges, and automated alerts; reduced review turnaround by **X%** and improved audit visibility with field-change tracking and `/admin/health` metrics. 
- Hardened security posture (policy UI, CSP cleanup, non-dev `SECRET_KEY`, admin-only backups). 
- CI/CD with GitHub Actions; pytest + flake8; coverage reports.

---

## 📄 License
MIT — see `LICENSE`.
