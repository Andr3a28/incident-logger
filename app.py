# =========================
# Incident Logger - single file app.py (SECURE, auto-signatures, exec dashboard, CSP nonce)
# =========================
import os
import threading
import shutil
import time
import platform
import json, io, csv, json, zipfile, secrets, string
from datetime import datetime, date, timedelta, timezone
from io import BytesIO
from functools import wraps
from urllib.parse import urlencode, urlparse, urljoin

from flask import (jsonify, 
    send_file, Flask, request, redirect, url_for, flash, session, abort,
    send_from_directory, make_response, render_template, g
, render_template_string
    )
from flask_sqlalchemy import SQLAlchemy

# Flask-WTF: forms + global CSRF
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf

from wtforms import StringField, PasswordField, TextAreaField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Regexp

from passlib.hash import pbkdf2_sha256
from xhtml2pdf import pisa
from jinja2 import DictLoader
from sqlalchemy import func

from werkzeug.utils import secure_filename
import math
# Optional: rate limiting for login (safe fallback if not installed)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _limiter_available = True
except Exception:
    _limiter_available = False

# -------------------------
# App & Config
# -------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLITE_URI', 'sqlite:///incident_logger.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))  # 10 MB default
# Idle timeout: 6 minutes
app.permanent_session_lifetime = timedelta(minutes=6)

# Cookie hardening (env-driven so dev over HTTP still works)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax'),
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', '0') == '1',
    REMEMBER_COOKIE_HTTPONLY=True,
)
if os.environ.get('PREFERRED_URL_SCHEME'):
    app.config['PREFERRED_URL_SCHEME'] = os.environ.get('PREFERRED_URL_SCHEME')

db = SQLAlchemy(app)

# Global CSRF
csrf = CSRFProtect(app)

# Optional Limiter
if _limiter_available:
    limiter = Limiter(get_remote_address, app=app, default_limits=[])
else:
    class _NoopLimiter:
        def limit(self, *_a, **_k):
            def _wrap(fn): return fn
            return _wrap
    limiter = _NoopLimiter()

# -------------------------
# CSP nonce per request (Option A)
# -------------------------
@app.before_request
def set_csp_nonce():
    # A fresh nonce on every request
    g.csp_nonce = secrets.token_urlsafe(16)

# Expose csrf_token() and the CSP nonce to templates
@app.context_processor
def inject_template_helpers():
    return dict(csrf_token=generate_csrf, csp_nonce=getattr(g, 'csp_nonce', ''))

# Prevent browser/page caching & add security headers (with nonce in CSP)
@app.after_request
def add_no_cache_headers(resp):
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    # Security headers
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # CSP tuned for Bootstrap + Google Fonts + Chart.js + NONCED inline script
    nonce = getattr(g, 'csp_nonce', '')
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        f"script-src 'self' https://cdn.jsdelivr.net 'nonce-{nonce}'; "
        "connect-src 'self'; frame-ancestors 'none';"
    )
    return resp

BACKUP_DIR = os.path.abspath(os.environ.get('BACKUP_DIR', './backups'))
os.makedirs(BACKUP_DIR, exist_ok=True)


UPLOAD_DIR = os.path.abspath(os.environ.get('UPLOAD_DIR', './uploads'))

# -------------------------
# Background health metrics
# -------------------------
HEALTH = {
    'started_at': datetime.now(timezone.utc),
    'last_run': None,
    'interval_seconds': 60,
    'metrics': {}
}
_HEALTH_STOP = threading.Event()
_HEALTH_THREAD = None
_JOBS_STARTED = False

def _empty(s):
    try:
        return (s or '').strip() == ''
    except Exception:
        return not bool(s)


def _compute_health_metrics():
    """Compute quick, safe health metrics; keep it lightweight."""
    metrics = {}
    try:
        db.session.execute(db.text('SELECT 1'))
        metrics['db_ok'] = True
    except Exception as e:
        metrics['db_ok'] = False
        metrics['db_error'] = str(e)[:200]

    # Database info
    try:
        metrics['db_dialect'] = db.engine.dialect.name
        metrics['db_uri'] = app.config.get('SQLALCHEMY_DATABASE_URI')
        if metrics['db_dialect'] == 'sqlite':
            # Estimate live DB size from PRAGMA
            try:
                pc = db.session.execute(db.text('PRAGMA page_count')).scalar() or 0
                ps = db.session.execute(db.text('PRAGMA page_size')).scalar() or 0
                metrics['db_size_bytes_estimated'] = int(pc) * int(ps)
            except Exception:
                pass
            # Try to get file path and file size
            uri = (metrics['db_uri'] or '').replace('sqlite:///', '')
            fpath = uri if uri and uri != ':memory:' else None
            if fpath and os.path.exists(fpath):
                metrics['db_file_path'] = fpath
                try:
                    metrics['db_file_size_bytes'] = os.path.getsize(fpath)
                except Exception:
                    pass
    except Exception:
        pass

    try:
        metrics['users'] = User.query.count()
    except Exception:
        metrics['users'] = None
    try:
        metrics['incidents_total'] = Incident.query.count()
        metrics['incidents_pending_im'] = db.session.query(Incident).filter(
            db.func.upper(db.func.coalesce(Incident.reviewer,'')) == 'IM',
            db.or_(Incident.im_comments.is_(None), db.func.trim(Incident.im_comments) == '') if hasattr(Incident, 'im_comments') else db.text('1=0')
        ).count()
        metrics['incidents_pending_sdm'] = db.session.query(Incident).filter(
            db.func.upper(db.func.coalesce(Incident.reviewer,'')) == 'SDM',
            db.or_(Incident.sdm_comments.is_(None), db.func.trim(Incident.sdm_comments) == '') if hasattr(Incident, 'sdm_comments') else db.text('1=0')
        ).count()
        metrics['incidents_pending_gm'] = db.session.query(Incident).filter(
            db.or_(Incident.governance_comments.is_(None), db.func.trim(Incident.governance_comments) == '') if hasattr(Incident, 'governance_comments') else db.text('1=0')
        ).count()
    except Exception:
        metrics['incidents_total'] = None
        metrics['incidents_pending_im'] = None
        metrics['incidents_pending_sdm'] = None
        metrics['incidents_pending_gm'] = None

    try:
        metrics['attachments_total'] = IncidentAttachment.query.count()
    except Exception:
        metrics['attachments_total'] = None

    # Process + disk info
    try:
        du = shutil.disk_usage(UPLOAD_DIR if 'UPLOAD_DIR' in globals() else '.')
        metrics['disk_free_mb'] = du.free // (1024*1024)
        metrics['disk_total_mb'] = du.total // (1024*1024)
    except Exception:
        pass

    metrics['python_version'] = platform.python_version()
    metrics['pid'] = os.getpid()

    HEALTH['metrics'] = metrics
    HEALTH['last_run'] = datetime.now(timezone.utc)
    return metrics


def _start_background_jobs():
    global _JOBS_STARTED, _HEALTH_THREAD
    if _JOBS_STARTED:
        return
    _JOBS_STARTED = True

    def runner():
        while not _HEALTH_STOP.is_set():
            try:
                with app.app_context():
                    _compute_health_metrics()
            except Exception:
                pass
            # Wait for interval or until stop signalled
            _HEALTH_STOP.wait(HEALTH.get('interval_seconds', 60))

    _HEALTH_THREAD = threading.Thread(target=runner, name='health-bg', daemon=True)
    _HEALTH_THREAD.start()

@app.before_request
def _start_jobs_once():
    # Fire once per process
    _start_background_jobs()

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Allowed attachment extensions (case-insensitive)
ALLOWED_ATTACH_EXT = set((
    'pdf','png','jpg','jpeg','gif','bmp','tiff','txt','log','csv','xlsx','xls','doc','docx','ppt','pptx','json','zip','gz','rar','7z'
))
PREFIX = 'NMB'
PAD = 6

# -------------------------
# Helpers: auth / roles
# -------------------------
def login_required(fn):
    @wraps(fn)
    def _wrap(*a, **kw):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        # idle timeout
        last = session.get('last_seen')
        now = datetime.now(timezone.utc).timestamp()
        if last and now - last > app.permanent_session_lifetime.total_seconds():
            logout_user()
            flash('Session timed out. Please log in again.', 'warning')
            return redirect(url_for('login'))
        session['last_seen'] = now
        return fn(*a, **kw)
    return _wrap

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        def _wrap(*a, **kw):
            if not session.get('user_id'):
                return redirect(url_for('login', next=request.path))
            if session.get('role') not in roles:
                abort(403)
            return fn(*a, **kw)
        return _wrap
    return deco

def current_username():
    return session.get('username') or 'anonymous'

def current_full_name_or_username():
    u = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
    return (u.full_name or u.username).strip() if u else current_username()

def fmt_date(d):
    if not d:
        return ''
    if isinstance(d, (datetime, date)):
        if isinstance(d, datetime):
            return d.astimezone(timezone.utc).strftime('%Y-%m-%d')
        return d.strftime('%Y-%m-%d')
    return str(d)

def _canonical_system_label(key: str) -> str:
    s = (key or '').strip()
    return s.title() if s else 'Unspecified'

# -------------------------
# Database Models
# -------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    title = db.Column(db.String(32), default='')
    first_name = db.Column(db.String(64), default='')
    last_name = db.Column(db.String(64), default='')
    role = db.Column(db.String(16), default='view')  # admin|sd|view|gm|cto|im|sdm
    is_disabled = db.Column(db.Boolean, default=False)
    force_password_change = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, pw): self.password_hash = pbkdf2_sha256.hash(pw)
    def check_password(self, pw): return pbkdf2_sha256.verify(pw, self.password_hash)
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), index=True)  # NMB-YYYY-000001
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date = db.Column(db.Date)
    incident_logger = db.Column(db.String(128))
    channel_or_system = db.Column(db.String(128))
    incident = db.Column(db.Text)
    time_of_incident = db.Column(db.String(64))
    time_of_resolution = db.Column(db.String(64))
    date_of_resolution = db.Column(db.Date)
    root_cause = db.Column(db.Text)
    impact = db.Column(db.Text)
    corrective_action = db.Column(db.Text)
    corrective_action_by = db.Column(db.String(128))
    reviewed_by = db.Column(db.String(128))           # backward compatibility
    reviewer_signature = db.Column(db.String(128))    # backward compatibility
    reviewer = db.Column(db.String(8))  # 'IM' or 'SDM'
    # --- IM/SDM review data ---
    im_comments = db.Column(db.Text)
    im_signature = db.Column(db.String(128))
    sdm_comments = db.Column(db.Text)
    sdm_signature = db.Column(db.String(128))
    # --------------------------
    governance_comments = db.Column(db.Text)
    governance_signature = db.Column(db.String(128))

class UnauthorizedChange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(24), index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date = db.Column(db.Date)
    system = db.Column(db.String(128))
    incident = db.Column(db.Text)
    time_occurred = db.Column(db.String(64))
    root_cause = db.Column(db.Text)
    impact = db.Column(db.Text)
    correction_taken = db.Column(db.Text)
    completed_by = db.Column(db.String(128))
    completed_by_title = db.Column(db.String(128))
    completed_by_signature = db.Column(db.String(128))
    section_manager = db.Column(db.String(128))
    section_manager_signature = db.Column(db.String(128))
    governance_manager = db.Column(db.String(128))
    governance_manager_signature = db.Column(db.String(128))
    hod = db.Column(db.String(128))
    hod_signature = db.Column(db.String(128))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    username = db.Column(db.String(64))
    action = db.Column(db.String(32))  # LOGIN/LOGOUT/CREATE/UPDATE/DELETE/EXPORT/LOCK/DELETE_REQUEST/DELETE_APPROVED/DELETE_REJECTED
    entity_type = db.Column(db.String(32))
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text)

class Sequence(db.Model):
    key = db.Column(db.String(32), primary_key=True)
    last_value = db.Column(db.Integer, default=0)

# --- NEW: two-person delete approval model ---
class DeleteRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entity_type = db.Column(db.String(32))   # e.g., 'incident', 'attachment'
    entity_id = db.Column(db.Integer, nullable=True)
    requested_by = db.Column(db.String(64))
    approved_by = db.Column(db.String(64), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(16), default='pending')  # pending/approved/rejected
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class PasswordPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    min_length = db.Column(db.Integer, default=12)
    require_upper = db.Column(db.Boolean, default=True)
    require_lower = db.Column(db.Boolean, default=True)
    require_number = db.Column(db.Boolean, default=True)
    require_special = db.Column(db.Boolean, default=True)
    expiry_days = db.Column(db.Integer, default=90)          # force change after N days
    lockout_threshold = db.Column(db.Integer, default=3)      # failed attempts before disable
    idle_timeout_minutes = db.Column(db.Integer, default=6)   # session idle timeout

def _get_policy():
    pol = PasswordPolicy.query.get(1)
    if not pol:
        pol = PasswordPolicy(id=1)
        db.session.add(pol)
        db.session.commit()
    return pol

def _build_password_validators(pol=None):
    pol = pol or _get_policy()
    validators = [Length(min=pol.min_length, message=f'Must be at least {pol.min_length} characters long')]
    if pol.require_upper: validators.append(Regexp(r'.*[A-Z].*', message='Must include at least one uppercase letter (A-Z)'))
    if pol.require_lower: validators.append(Regexp(r'.*[a-z].*', message='Must include at least one lowercase letter (a-z)'))
    if pol.require_number: validators.append(Regexp(r'.*[0-9].*', message='Must include at least one number (0-9)'))
    if pol.require_special: validators.append(Regexp(r'.*[^A-Za-z0-9].*', message='Must include at least one special character (e.g., !@#$%)'))
    return validators

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    entity_type = db.Column(db.String(32))     # 'Incident' or 'User'
    entity_id = db.Column(db.Integer)
    reason = db.Column(db.Text)
    requested_by = db.Column(db.String(64))
    approved_by = db.Column(db.String(64), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(16), default='pending')  # pending|approved|rejected|cancelled



class System(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True)

class IncidentAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), index=True, nullable=False)
    original_name = db.Column(db.String(255))
    stored_name = db.Column(db.String(255))  # basename we store on disk
    stored_path = db.Column(db.String(512))   # relative to UPLOAD_DIR
    content_type = db.Column(db.String(120))
    size_bytes = db.Column(db.Integer)
    uploaded_by = db.Column(db.String(64))
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
# -------------------------
# Business helpers
# -------------------------



# =========================
# RBAC: Roles & Privileges
# =========================
# Association tables
role_privilege = db.Table(
    'role_privilege',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('privilege_id', db.Integer, db.ForeignKey('privilege.id'), primary_key=True)
)

user_role = db.Table(
    'user_role',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)  # e.g., admin, sd, im, sdm, gm, view, cto
    description = db.Column(db.String(255), default='')
    is_active = db.Column(db.Boolean, default=True)
    privileges = db.relationship('Privilege', secondary=role_privilege, backref='roles', lazy='joined')

class Privilege(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False)  # e.g., can_view_records
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(255), default='')

# Attach roles relationship to existing User model without editing the class block
try:
    User.roles = db.relationship('Role', secondary=user_role, backref='users', lazy='joined')
except Exception as _ex:
    # In case User is not yet defined at import time; will be bound later
    pass

# Privilege catalog and default role mappings
PRIV_CATALOG = [
    ('can_view_dashboard', 'View Dashboard'),
    ('can_view_records', 'View Records list'),
    ('can_create_incident', 'Create Incident'),
    ('can_review_im', 'Review as IM'),
    ('can_review_sdm', 'Review as SDM'),
    ('can_view_audit', 'View Audit Log'),
    ('can_export_data', 'Export CSV/PDF/ZIP'),
    ('can_manage_users', 'Manage Users'),
    ('can_manage_roles', 'Manage Roles & Privileges'),
    ('can_manage_systems', 'Manage Systems list'),
    ('can_manage_password_policy', 'Manage Password Policy'),
    ('can_backup', 'Download Backup'),
    ('can_raise_delete', 'Raise Delete Request'),
    ('can_approve_delete', 'Approve/Reject Delete Requests'),
    ('can_view_settings', 'View Settings/Administration'),
    ('can_upload_attachments', 'Upload Attachments'),
    ('can_download_attachments', 'Download Attachments'),
    ('can_delete_attachments', 'Delete Attachments'),
    ('is_admin', 'Admin (superuser flag)'),
    ('view_only', 'View Only'),
    ('can_log_incident', 'Log/Create Incident'),
    ('can_review_incident', 'Review Incident (any)'),
]

DEFAULT_ROLE_PRIVS = {
    'admin': [
        'can_view_dashboard','can_view_records','can_create_incident','can_review_im','can_review_sdm',
        'can_view_audit','can_export_data','can_manage_users','can_manage_roles','can_manage_systems',
        'can_manage_password_policy','can_backup','can_raise_delete','can_approve_delete',
        'can_view_settings','can_upload_attachments','can_download_attachments','can_delete_attachments'
    ],
    'sd': ['can_view_dashboard','can_view_records','can_create_incident','can_export_data',
           'can_raise_delete','can_upload_attachments','can_download_attachments'],
    'im': ['can_view_dashboard','can_view_records','can_review_im','can_export_data',
           'can_upload_attachments','can_download_attachments'],
    'sdm': ['can_view_dashboard','can_view_records','can_review_sdm','can_export_data',
            'can_upload_attachments','can_download_attachments'],
    'gm': ['can_view_dashboard','can_view_records','can_view_audit','can_export_data','can_backup',
           'can_approve_delete','can_upload_attachments','can_download_attachments'],
    'view': ['can_view_dashboard','can_view_records','can_download_attachments'],
    'cto': ['can_view_dashboard','can_view_records','can_view_audit','can_export_data','can_backup',
            'can_upload_attachments','can_download_attachments']
}

def ensure_privileges_and_roles():
    # Idempotent seeding
    created = []
    for code, name in PRIV_CATALOG:
        obj = Privilege.query.filter_by(code=code).first()
        if not obj:
            obj = Privilege(code=code, name=name)
            db.session.add(obj); created.append(f"priv:{code}")
    db.session.commit()

    for rname, codes in DEFAULT_ROLE_PRIVS.items():
        r = Role.query.filter_by(name=rname).first()
        if not r:
            r = Role(name=rname, description=f"Default role: {rname}")
            db.session.add(r); db.session.flush()
        # attach privileges
        privs = Privilege.query.filter(Privilege.code.in_(codes)).all()
        # Avoid duplicates
        existing = {p.code for p in r.privileges}
        for p in privs:
            if p.code not in existing:
                r.privileges.append(p)
        created.append(f"role:{rname}")
    db.session.commit()
    return created

def _user_priv_codes(u):
    codes = set()
    # Roles via many-to-many
    if hasattr(u, 'roles') and u.roles:
        for r in u.roles:
            for p in (r.privileges or []):
                codes.add(p.code)
    # Fallback: string role mapping
    if hasattr(u, 'role') and u.role:
        for c in DEFAULT_ROLE_PRIVS.get(u.role, []):
            codes.add(c)
    return codes

def has_privilege(code):
    if not session.get('user_id'):
        return False
    u = db.session.get(User, session['user_id'])
    return code in _user_priv_codes(u)

def privs_required(*codes):
    def deco(fn):
        @wraps(fn)
        def _wrap(*a, **kw):
            if not session.get('user_id'):
                return redirect(url_for('login', next=request.path))
            u = db.session.get(User, session['user_id'])
            user_codes = _user_priv_codes(u)
            if not all(c in user_codes for c in codes):
                abort(403)
            return fn(*a, **kw)
        return _wrap
    return deco

# Seed on import (safe if run more than once)
try:
    ensure_privileges_and_roles()
except Exception as _seed_ex:
    # DB might not be ready during first import; will attempt during first request
    pass

def _safe_subdir(name: str) -> str:
    return ''.join(c if c.isalnum() or c in ('-','_') else '-' for c in name)

def _save_incident_attachments(rec, files):
    """Save uploaded files for an incident."""
    saved = []
    if not files: 
        return saved
    subdir = os.path.join('incident', _safe_subdir(rec.number or f'id-{rec.id}'))
    dest_dir = os.path.join(UPLOAD_DIR, subdir)
    os.makedirs(dest_dir, exist_ok=True)
    for f in files:
        if not f or not getattr(f, 'filename', None):
            continue
        filename = f.filename
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext and ext not in ALLOWED_ATTACH_EXT:
            # silently skip unsupported types; the UI can show guidance if needed
            continue
        base = secure_filename(filename) or f"file-{secrets.token_hex(4)}"
        unique = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(6)}-{base}"
        path = os.path.join(dest_dir, unique)
        try:
            f.save(path)
            size = os.path.getsize(path) if os.path.exists(path) else 0
            att = IncidentAttachment(
                incident_id=rec.id,
                original_name=filename,
                stored_name=os.path.basename(unique),
                stored_path=os.path.join(subdir, unique),
                content_type=getattr(f, 'mimetype', '') or '',
                size_bytes=size,
                uploaded_by=current_username()
            )
            db.session.add(att)
            saved.append(att)
        except Exception as e:
            # Best-effort; if save fails, skip that file
            print('[upload] failed to save attachment:', e)
    if saved:
        db.session.commit()
    return saved
def is_incident_complete(rec: Incident) -> bool:
    return bool(rec.governance_comments and rec.governance_comments.strip())

def gm_can_comment(rec: Incident) -> bool:
    """GM may comment only after the assigned reviewer (IM/SDM) has
    provided both a comment and a signature. If no reviewer set, allow GM."""
    rev = (rec.reviewer or '').upper()
    if rev == 'IM':
        return not needs_im_on_incident(rec)
    if rev == 'SDM':
        return not needs_sdm_on_incident(rec)
    return True

def needs_gm_on_unauth(u: UnauthorizedChange) -> bool:
    return not (u.governance_manager and str(u.governance_manager).strip() and
                u.governance_manager_signature and str(u.governance_manager_signature).strip())

def needs_hod_on_unauth(u: UnauthorizedChange) -> bool:
    return not (u.hod and str(u.hod).strip() and
                u.hod_signature and str(u.hod_signature).strip())

def is_unauth_complete(rec: UnauthorizedChange) -> bool:
    return not (needs_gm_on_unauth(rec) or needs_hod_on_unauth(rec))

def next_number(kind: str) -> str:
    year = datetime.now(timezone.utc).year
    key = f"{kind}_{year}"
    seq = db.session.get(Sequence, key)
    if not seq:
        seq = Sequence(key=key, last_value=0)
        db.session.add(seq)
        db.session.commit()
    seq.last_value += 1
    db.session.commit()
    return f"{PREFIX}-{year}-{str(seq.last_value).zfill(PAD)}"

def log_audit(action, entity_type, entity_id, details):
    db.session.add(AuditLog(username=current_username(), action=action,
                            entity_type=entity_type, entity_id=entity_id, details=details))
    db.session.commit()

def logout_user():
    if session.get('user_id'):
        log_audit('LOGOUT', 'User', session['user_id'], f"{session.get('username')} logged out")
    session.clear()

def _empty(v):
    return v is None or str(v).strip() == ''

def needs_im_on_incident(rec):
    return _empty(rec.im_comments) or _empty(rec.im_signature)

def needs_sdm_on_incident(rec):
    return _empty(rec.sdm_comments) or _empty(rec.sdm_signature)


def reviewer_has_commented(rec: Incident) -> bool:
    """True once the assigned reviewer (IM/SDM) has provided a comment.
    This is *stricter* than edit lock based on signature; here we only
    check comments per user request (lock as soon as a comment exists)."""
    rev = (rec.reviewer or '').strip().upper()
    if rev == 'IM':
        return bool(rec.im_comments and str(rec.im_comments).strip())
    if rev == 'SDM':
        return bool(rec.sdm_comments and str(rec.sdm_comments).strip())
    return False

# -------------------------
# Password policy (validators)
# -------------------------
PASSWORD_POLICY = [
    Length(min=12, message='Must be at least 12 characters long'),
    Regexp(r'.*[A-Z].*', message='Must include at least one uppercase letter (A-Z)'),
    Regexp(r'.*[a-z].*', message='Must include at least one lowercase letter (a-z)'),
    Regexp(r'.*[^A-Za-z0-9].*', message='Must include at least one special character (e.g., !@#$%)'),
]

# -------------------------
# Forms
# -------------------------
class LoginForm(FlaskForm):
    username = StringField('Username', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Current Password', [DataRequired()])
    new_password = PasswordField('New Password', [DataRequired()] + PASSWORD_POLICY)
    confirm = PasswordField('Confirm New Password', [DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class IncidentForm(FlaskForm):
    date = DateField('Date', [DataRequired()], default=date.today)
    incident_logger = StringField('Logged By', [DataRequired(), Length(max=128)])
    channel_or_system = SelectField('System/Channel', choices=[], validators=[DataRequired()])
    incident = TextAreaField('Incident', [DataRequired()])
    # 24h time (HH:MM)
    time_of_incident = StringField('Time of Incident', [Optional(), Regexp(r'^([01]\d|2[0-3]):[0-5]\d$', message='Use HH:MM (24h)')])
    time_of_resolution = StringField('Time of Resolution', [Optional(), Regexp(r'^([01]\d|2[0-3]):[0-5]\d$', message='Use HH:MM (24h)')])
    date_of_resolution = DateField('Date of Resolution', [Optional()])
    root_cause = TextAreaField('Root Cause')
    impact = TextAreaField('Impact')
    corrective_action = TextAreaField('Corrective Action')
    corrective_action_by = StringField('Corrective Action By')
    reviewer = SelectField('Reviewer', choices=[('IM','Infrastructure Manager'), ('SDM','Service Delivery Manager')])
    submit = SubmitField('Save')

class IncidentGovForm(FlaskForm):
    governance_comments = TextAreaField('Governance Comments', [DataRequired()])
    governance_signature = StringField('Governance Signature', [Optional(), Length(max=128)])
    submit = SubmitField('Save')

class UnauthForm(FlaskForm):
    date = DateField('Date', [DataRequired()], default=date.today)
    system = StringField('System', [DataRequired(), Length(max=128)])
    incident = TextAreaField('Narrative', [DataRequired()])
    time_occurred = StringField('Time Occurred', [Length(max=64)])
    root_cause = TextAreaField('Root Cause')
    impact = TextAreaField('Impact')
    correction_taken = TextAreaField('Correction Taken')
    completed_by = StringField('Completed By')
    completed_by_title = StringField('Completed By Title')
    completed_by_signature = StringField('Completed By Signature')
    section_manager = StringField('Section Manager')
    section_manager_signature = StringField('Section Manager Signature')
    submit = SubmitField('Save')

class UnauthGovForm(FlaskForm):
    governance_manager = StringField('Governance Manager', [DataRequired()])
    governance_manager_signature = StringField('Governance Manager Signature', [DataRequired()])
    submit = SubmitField('Save')

# Reviewer forms (IM/SDM) — signature is optional in form; server enforces real signer.
class IMReviewForm(FlaskForm):
    im_comments = TextAreaField('Infrastructure Manager Comment', [DataRequired()])
    im_signature = StringField('Infrastructure Manager Signature', [Optional(), Length(max=128)])
    submit = SubmitField('Save')

class SDMReviewForm(FlaskForm):
    sdm_comments = TextAreaField('Service Delivery Manager Comment', [DataRequired()])
    sdm_signature = StringField('Service Delivery Manager Signature', [Optional(), Length(max=128)])
    submit = SubmitField('Save')

# ----- Missing forms for user management (included) -----
TITLE_CHOICES = [
    ('', ''), ('Mr', 'Mr'), ('Mrs', 'Mrs'), ('Ms', 'Ms'),
    ('Dr', 'Dr'), ('Eng', 'Eng'), ('Prof', 'Prof')
]
ROLE_CHOICES = [
    ('admin', 'Admin'),
    ('sd', 'Service Desk'),
    ('ne', 'Networking Engineer'),
    ('im', 'Infrastructure Manager'),
    ('sdm', 'Service Delivery Manager'),
    ('gm', 'Governance Manager'),
    ('cto', 'CTO'),
    ('view', 'Viewer'),
]

class NewUserForm(FlaskForm):
    title = SelectField('Title', choices=TITLE_CHOICES, default='')
    first_name = StringField('First name', [DataRequired(), Length(max=64)])
    last_name = StringField('Last name', [DataRequired(), Length(max=64)])
    username = StringField('Username', [DataRequired(), Length(min=3, max=64)])
    role = SelectField('Role', choices=ROLE_CHOICES, validators=[DataRequired()])
    password = PasswordField('Password', [DataRequired()] + PASSWORD_POLICY)
    submit = SubmitField('Create')

class ResetUserForm(FlaskForm):
    username = StringField('Username', [DataRequired(), Length(min=3, max=64)])
    new_password = PasswordField('New Password', [DataRequired()] + PASSWORD_POLICY)
    submit = SubmitField('Reset Password')

class EditUserForm(FlaskForm):
    title = SelectField('Title', choices=TITLE_CHOICES, default='')
    first_name = StringField('First name', [DataRequired(), Length(max=64)])
    last_name = StringField('Last name', [DataRequired(), Length(max=64)])
    username = StringField('Username', [DataRequired(), Length(min=3, max=64)])
    submit = SubmitField('Save')

# -------------------------
# Templates via DictLoader
# -------------------------
BASE_HTML = """
{% set me = session.get('username') %}
{% set role = session.get('role') %}
{% set ep = request.endpoint or '' %}
{% set alerts_from_session = session.get('alert_count', 0) %}
{% set alerts_from_g = g.alert_count if g is defined and g and g.get('alert_count') is not none else 0 %}
{% set alerts_from_ctx = alert_count if alert_count is defined else 0 %}
{% set alerts_total = (alerts_from_session or 0) + (alerts_from_g or 0) + (alerts_from_ctx or 0) %}
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ title or 'Incident Logger' }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  body{ background: var(--bs-body-bg); color: var(--bs-body-color); }
  .navbar-brand{ font-weight:600; letter-spacing:.2px; }
  .blink{ animation: blink 1s linear infinite; }
  @keyframes blink{ 50% { color:#dc3545; } }
  .status-badge{ border-radius:999px; padding:.15rem .5rem; font-size:.8rem; }
  .sys-card{
    transition: transform .15s ease, box-shadow .15s ease, background-color .15s ease;
    border: 1px solid var(--bs-border-color);
    border-left-width: 6px;
    border-radius: 14px;
    background: var(--bs-card-bg);
  }
  .sys-card:hover{ transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.12); background-color: rgba(0,0,0,.02); }
  .sys-chip{ display:inline-block; padding:.15rem .5rem; border-radius:999px; font-size:.8rem; color:#fff; }
  .card-soft{ border-radius:16px; box-shadow: 0 6px 18px rgba(0,0,0,.06); }
  .table-sm th, .table-sm td{ padding:.5rem .6rem; }
  .readonly-block{ white-space: pre-wrap; background:#f8f9fa; border:1px solid #e9ecef; border-radius:8px; padding:.5rem .75rem; }
  .label-sm{ font-size:.8rem; color:#6c757d; }
  pre { white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere; }
  .table td, .table th { vertical-align: top; }

  :root,[data-bs-theme="light"]{
    --app-card-bg: var(--bs-card-bg, #fff);
    --app-card-border: var(--bs-border-color, #e9ecef);
    --app-muted: var(--bs-secondary-color, #6c757d);
    --app-badge-bg: var(--bs-secondary-bg, #f1f3f5);
  }
  [data-bs-theme="dark"]{
    --app-card-bg: var(--bs-card-bg, #1e1e1e);
    --app-card-border: var(--bs-border-color, #2a2a2a);
    --app-muted: var(--bs-secondary-color, #c0c4c8);
    --app-badge-bg: #2b2f33;
  }
  .card, .card-soft{ background: var(--app-card-bg); border-color: var(--app-card-border); }
  .card-soft{ border: 1px solid var(--app-card-border); border-radius: .75rem; box-shadow: 0 .5rem 1rem rgba(0,0,0,.05); }
  .text-muted,.muted{ color: var(--app-muted) !important; }
  .badge.bg-soft{ background: var(--app-badge-bg); color: var(--bs-body-color); }
  .table{ color: var(--bs-body-color); }
  .table thead th{ color: var(--bs-body-color); }
  .list-group-item{ background: var(--app-card-bg); color: var(--bs-body-color); }
  .sys-tile{ background: var(--app-card-bg); border:1px solid var(--app-card-border); border-radius: 14px; padding:14px; display:flex; justify-content:space-between; align-items:center; }
  .sys-tile .count{ font-weight:700; }
  .sys-tile .label{ opacity:.8; }

  /* Enlarge top nav items */
  .navbar-nav .nav-link{
    font-size: 1.06rem;
    font-weight: 500;
    padding: .6rem .9rem;
  }
  @media (max-width: 991.98px){
    .navbar-nav .nav-link{ font-size: 1rem; padding: .5rem .75rem; }
  }


  /* Active + hover underline for top nav */
  .navbar-nav .nav-link{ position: relative; transition: color .15s ease; }
  .navbar-nav .nav-link:hover{ color: var(--bs-primary); }
  .navbar-nav .nav-link.active::after{
    content: "";
    position: absolute;
    left: .75rem; right: .75rem; bottom: .35rem;
    height: 2px; background: var(--bs-primary); border-radius: 2px;
  }

</style>
</head>
<body>
<nav class="navbar navbar-expand-lg bg-body shadow-sm">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('index') }}">Incident Logger</a>
    <button class="navbar-toggler" data-bs-toggle="collapse" data-bs-target="#nav">☰</button>
    <div class="collapse navbar-collapse" id="nav">
      {% if session.get('user_id') %}

      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="{{ url_for(\'records\') }}" class="nav-link {{ 'active' if ep in ['records'] else '' }}">View Records</a></li>

        {% if role in ['gm','sdm','im'] %}
          <li class="nav-item">
            <a class="nav-link {% if alerts_total|int > 0 %}blink{% endif %}" href="{{ url_for('alerts') }}">
              Alerts
              {% if alerts_total|int > 0 %}
                <span class="badge rounded-pill text-bg-danger ms-1">{{ alerts_total }}</span>
              {% endif %}
            </a>
          </li>
        {% endif %}

        {% if role in ['admin','sd','ne'] %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for(\'new_incident\') }}" class="nav-link {{ 'active' if ep in ['new_incident'] else '' }}">New Incident</a></li>
        {% endif %}
        {% if role in ['admin','sd','view'] %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for(\'audit\') }}" class="nav-link {{ 'active' if ep in ['audit'] else '' }}">Audit</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for(\'view_users\') }}" class="nav-link {{ 'active' if ep in ['view_users'] else '' }}">Users</a></li>
        {% endif %}
        {% if role == 'admin' %}
          
          <li class="nav-item"><a class="nav-link {{ 'active' if ep in ['password_policy'] else '' }}" href="{{ url_for('password_policy') }}">Password Policy</a></li>
          <li class="nav-item"><a class="nav-link {{ 'active' if ep in ['view_roles','new_role','edit_role'] else '' }}" href="{{ url_for('view_roles') }}">Roles</a></li>
 <li class="nav-item"><a class="nav-link" href="{{ url_for(\'admin_settings\') }}" class="nav-link {{ 'active' if ep in ['admin_settings'] else '' }}">Settings</a></li>
<li class="nav-item"><a class="nav-link {{ 'active' if ep in ['admin_health'] else '' }}" href="{{ url_for('admin_health') }}">Health</a></li>
<li class="nav-item"><a class="nav-link {{ 'active' if ep in ['backup'] else '' }}" href="{{ url_for('backup') }}">Backup</a></li>
        {% endif %}
      </ul>

      <!-- Profile dropdown on the far right -->
      <ul class="navbar-nav ms-auto">
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle d-flex align-items-center gap-2" href="#" id="profileMenu" role="button" data-bs-toggle="dropdown" aria-expanded="false">
            <span class="fw-semibold">{{ me }}</span>
            <span class="text-muted">({{ role }})</span>
          </a>
          <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="profileMenu">
            <li><a class="dropdown-item" href="{{ url_for('change_password') }}">Change Password</a></li>
            <li><button class="dropdown-item" id="themeToggleItem" type="button">Change Theme</button></li>
            <li><hr class="dropdown-divider"></li>
            <li>
  <form method="post" action="{{ url_for('logout') }}" class="px-3 my-1">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button class="dropdown-item text-danger">Logout</button>
  </form>
</li>
          </ul>
        </li>
      </ul>

      {% endif %}
    </div>
  </div>
</nav>

<div class="container mt-4">
  {% with msgs = get_flashed_messages(with_categories=true) %}
    {% if msgs %}
      {% for cat,msg in msgs %}
        <div class="alert alert-{{cat}} alert-dismissible fade show" role="alert">
          {{ msg }}
          <button class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% block body %}{% endblock %}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script nonce="{{ csp_nonce }}">
(function(){
  const KEY = 'theme';
  const root = document.documentElement;
  function apply(t){
    root.setAttribute('data-bs-theme', t);
    try{ localStorage.setItem(KEY, t); }catch(e){}
  }
  let saved = 'light';
  try{ saved = localStorage.getItem(KEY) || 'light'; }catch(e){}
  apply(saved);

  function toggle(){
    let now = root.getAttribute('data-bs-theme') || 'light';
    apply(now === 'light' ? 'dark' : 'light');
    document.dispatchEvent(new CustomEvent('theme-change'));
  }

  // Dropdown "Change Theme" click
  document.addEventListener('click', function(e){
    if(e.target && e.target.id === 'themeToggleItem'){
      toggle();
    }
  });
})();
</script>

<script nonce="{{ csp_nonce }}">
// If you have Plotly charts, keep them in sync with theme changes
(function(){
  function applyChartTheme(theme){
    if(!window.Plotly) return;
    var ids = ['trendChart','dailyChart','volumeChart'];
    var layout = {
      paper_bgcolor: 'rgba(0,0,0,0)',
      plot_bgcolor: 'rgba(0,0,0,0)',
      font: {color: getComputedStyle(document.body).getPropertyValue('--bs-body-color')}
    };
    ids.forEach(function(id){
      var el = document.getElementById(id);
      if(el){ try{ Plotly.relayout(el, layout); }catch(e){} }
    });
  }
  document.addEventListener('theme-change', function(){
    var now = document.documentElement.getAttribute('data-bs-theme') || 'light';
    applyChartTheme(now);
  });
  document.addEventListener('DOMContentLoaded', function(){
    var now = document.documentElement.getAttribute('data-bs-theme') || 'light';
    applyChartTheme(now);
  });
})();
</script>

</body></html>
"""

LOGIN_HTML = """
{% extends "base.html" %}{% block body %}
<div class="row justify-content-center">
 <div class="col-md-6">
  <div class="card card-soft p-4">
   <h4 class="mb-3">Login</h4>
   <form method="post" enctype="multipart/form-data" autocomplete="off">
     {{ form.hidden_tag() }}
     <div class="mb-3">{{ form.username.label }} {{ form.username(class="form-control", autocomplete="off", autocapitalize="none", spellcheck="false") }}</div>
     <div class="mb-3">{{ form.password.label }} {{ form.password(class="form-control", autocomplete="off") }}</div>
     <button class="btn btn-primary">{{ form.submit.label.text }}</button>
   </form>
  </div>
 </div>
</div>
{% endblock %}
"""

# ======= Executive dashboard template (updated with nonce) =======
INDEX_HTML = """{% extends "base.html" %}{% block body %}

<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
  :root,[data-bs-theme="light"]{
    --bg: var(--bs-body-bg);
    --card: var(--bs-card-bg, #fff);
    --muted: var(--bs-secondary-color, #6b7280);
    --edge: var(--bs-border-color, #e9edf3);
    --ink: var(--bs-body-color, #0f172a);
    --accent:#1363df; --ok:#10b981; --warn:#f59f00; --danger:#ef4444;
    --shadow: 0 10px 30px rgba(0,0,0,.10);
  }
  [data-bs-theme="dark"]{
    --bg: #0f1115;
    --card: #171a20;
    --muted: #cbd5e1;
    --edge: #252a33;
    --ink: #e6e7eb;
    --shadow: 0 12px 32px rgba(0,0,0,.45);
  }
  html,body{background:var(--bg)}
  .kpi{background:var(--card); border:1px solid var(--edge); border-radius:14px; padding:18px; box-shadow: var(--shadow);}
  .kpi .label{ color:var(--muted); font-size:.9rem }
  .kpi .value{ font: 800 24px/1.1 Inter,system-ui }
  .kpi .dot{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px }
  .kpi .dot.blue{ background:#2b6cff } .kpi .dot.red{ background:#ef4444 } .kpi .dot.amber{ background:#f59f00 } .kpi .dot.green{ background:#10b981 }
  .chart-card{ background:var(--card); border:1px solid var(--edge); border-radius:14px; padding:12px 16px; box-shadow: var(--shadow); }
  .chart-card h6{ color:var(--muted); font-weight:600 }
  .recent{ background:var(--card); border:1px solid var(--edge); border-radius:14px; box-shadow: var(--shadow); }
  .recent .table{ --bs-table-bg: transparent; }
  .sys-grid{ display:grid; gap:14px; grid-template-columns: repeat(3, 1fr); }
  @media (max-width: 900px){ .sys-grid{ grid-template-columns: repeat(2, 1fr); } }
  .sys-card{
    transition: transform .15s ease, box-shadow .15s ease, background-color .15s ease;
    border: 1px solid var(--edge);
    border-left-width: 6px;
    border-radius: 14px;
    background: var(--card);
  padding-left: 10px; background-clip: padding-box; }
  .sys-card:hover{ transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.18); background-color: rgba(255,255,255,0.02); }
  [data-bs-theme="dark"] .sys-card:hover{ background-color: rgba(255,255,255,0.04); }
  .sys-chip{ display:inline-block; padding:.15rem .5rem; border-radius:999px; font-size:.8rem; color:#fff; opacity:.9 }
  .sys-meta{ color: var(--muted); font-size:.85rem; padding-left: 2px }
</style>


<div class="d-flex align-items-end justify-content-between mb-3">
  <h4 class="mb-0">Executive Dashboard</h4>
  {% if (alert_count or 0) > 0 %}
    
  {% endif %}
</div>

<!-- KPIs -->
<div class="row g-3 mb-3">
  <div class="col-12 col-md-6 col-xl-3">
    <div class="kpi">
      <div class="dot" style="background:var(--accent)"></div>
      <div>
        <div class="val">{{ total_incidents }}</div>
        <div class="lbl">Total Incidents</div>
      </div>
    </div>
  </div>
  <div class="col-12 col-md-6 col-xl-3">
    <div class="kpi">
      <div class="dot" style="background:var(--danger)"></div>
      <div>
        <div class="val">{{ open_incidents }}</div>
        <div class="lbl">Pending GM comment</div>
      </div>
    </div>
  </div>
  <div class="col-12 col-md-6 col-xl-3">
    <div class="kpi">
      <div class="dot" style="background:var(--warn)"></div>
      <div>
        <div class="val">{{ awaiting_im }}</div>
        <div class="lbl">IM backlog</div>
      </div>
    </div>
  </div>
  <div class="col-12 col-md-6 col-xl-3">
    <div class="kpi">
      <div class="dot" style="background:var(--ok)"></div>
      <div>
        <div class="val">{{ awaiting_sdm }}</div>
        <div class="lbl">SDM backlog</div>
      </div>
    </div>
  </div>
</div>

<!-- Trend + Recent -->
<div class="row g-3">
  <div class="col-lg-7">
    <div class="card-soft p-3">
      <div class="d-flex justify-content-between align-items-center">
        <h6 class="mb-0">Last 14 Days</h6>
        <span class="text-muted small">Daily incident volume</span>
      </div>
      <canvas id="trend" height="140" class="mt-2"></canvas>
    </div>
  </div>
  <div class="col-lg-5">
    <div class="card-soft p-3">
      <h6 class="mb-2">Recent Incidents</h6>
      <table class="table table-sm table-hover align-middle mb-0">
        <thead><tr><th>#</th><th>Date</th><th>System</th><th class="text-end">Status</th></tr></thead>
        <tbody>
          {% for r in recent %}
            <tr>
              <td><a class="text-decoration-none" href="{{ url_for('record_view', kind='incident', rid=r.id) }}">{{ r.number }}</a></td>
              <td class="text-muted small">{{ r.date }}</td>
              <td>{{ r.system }}</td>
              <td class="text-end">
                {% if r.complete %}
                  <span class="badge bg-success">Complete</span>
                {% else %}
                  <span class="badge bg-danger blink">Pending</span>
                {% endif %}
              </td>
            </tr>
          {% else %}
            <tr><td colspan="4" class="text-muted">No incidents yet.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Systems -->
<div class="card-soft p-3 mt-3">
  <h6 class="mb-3">Incidents by System</h6>
  <div class="row row-cols-1 row-cols-md-2 row-cols-xl-3 g-3">
    {% set palette = ['#1f7ae0','#f59f00','#2ca02c','#e83e8c','#9467bd','#17a2b8'] %}
    {% for item in inc_by_system %}
      {% set color = palette[loop.index0 % (palette|length)] %}
      <div class="col">
        <a class="text-decoration-none text-reset" href="{{ url_for('records', sys=item.system|lower) }}">
          <div class="sys-card" style="border-left-color: {{color}};">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <div class="fw-semibold">{{ item.system or 'Unspecified' }}</div>
                <div class="text-muted small">Incidents</div>
              </div>
              <span class="sys-chip" style="background: {{color}};">{{ item.count }}</span>
            </div>
          </div>
        </a>
      </div>
    {% endfor %}
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script nonce="{{ csp_nonce }}">
  const labels = {{ series_labels|tojson }};
  const values = {{ series_values|tojson }};
  const el = document.getElementById('trend');
  const hasData = values.some(v => v > 0);
  if (!hasData) {
    el.outerHTML = '<div class="p-4 text-muted">No incidents in the last 14 days.</div>';
  } else {
    const ctx = el.getContext('2d');
    new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Incidents',
          data: values,
          fill: true,
          tension: .35
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display:false } },
          y: { beginAtZero:true, ticks:{ precision:0 }, grid:{ color:'rgba(0,0,0,.06)' } }
        }
      }
    });
  }
</script>
{% endblock %}
"""

# ========= IMPROVED RECORDS PAGE =========
RECORDS_HTML = """
{% extends "base.html" %}{% block body %}
<style>
  .kpi{display:flex;align-items:center;gap:.65rem;padding:.65rem .8rem;border:1px solid #e9edf3;background:#fff;border-radius:12px}
  .kpi .dot{width:12px;height:12px;border-radius:999px}
  .kpi .val{font-size:1.2rem;font-weight:800;line-height:1}
  .kpi .lbl{font-size:.8rem;color:#6b7280}
  thead.sticky th{position:sticky;top:0;background:#fff;z-index:2}
  tr.row-link{cursor:pointer}
  tr.row-link.table-warning{--bs-table-bg: #fffaf2;}
  .th-sortable{user-select:none;cursor:pointer}
  .th-sortable .sort-caret{opacity:.35;margin-left:.3rem}
  .th-active .sort-caret{opacity:1}
</style>

<h5 class="mb-3">Records</h5>

<form class="row g-2 mb-3 align-items-end" method="get" autocomplete="off">
  <div class="col-sm-3"><label class="form-label small">Text/System/Number</label><input name="q" value="{{ request.args.get('q','') }}" class="form-control" placeholder="Search..." autocomplete="off"></div>
  <div class="col-sm-3"><label class="form-label small">Person</label><input name="name" value="{{ request.args.get('name','') }}" class="form-control" placeholder="Person name" autocomplete="off"></div>
  <div class="col-sm-2"><label class="form-label small">From</label><input type="date" name="from" value="{{ request.args.get('from','') }}" class="form-control" autocomplete="off"></div>
  <div class="col-sm-2"><label class="form-label small">To</label><input type="date" name="to" value="{{ request.args.get('to','') }}" class="form-control" autocomplete="off"></div>
  <div class="col-sm-2 d-grid d-sm-flex gap-2">
    <button class="btn btn-primary">Filter</button>
    <a class="btn btn-outline-secondary" href="{{ url_for('records') }}">Clear</a>
    {% if export_count > 0 %}
      <a class="btn btn-success" href="{{ export_url }}">Download All ({{ export_count }})</a>
    {% endif %}
  </div>
</form>

<div class="row g-2 mb-3">
  <div class="col-sm-4 col-lg-3"><div class="kpi"><span class="dot" style="background:#1363df"></span><div><div class="val">{{ total_count }}</div><div class="lbl">Total</div></div></div></div>
  <div class="col-sm-4 col-lg-3"><div class="kpi"><span class="dot" style="background:#10b981"></span><div><div class="val">{{ complete_count }}</div><div class="lbl">Complete</div></div></div></div>
  <div class="col-sm-4 col-lg-3"><div class="kpi"><span class="dot" style="background:#ef4444"></span><div><div class="val">{{ open_count }}</div><div class="lbl">Pending GM</div></div></div></div>
</div>

<div class="card card-soft p-3">
  <div class="d-flex justify-content-between align-items-center mb-2">
    <h6 class="mb-0">Incidents</h6>
    <div class="btn-group btn-group-sm" role="group" aria-label="Quick filter">
      <button type="button" class="btn btn-outline-secondary" data-filter="all">All</button>
      <button type="button" class="btn btn-outline-success" data-filter="complete">Complete</button>
      <button type="button" class="btn btn-outline-danger" data-filter="pending">Pending</button>
    </div>
  </div>

  <div class="table-responsive">
    <table id="incTable" class="table table-sm table-hover align-middle mb-0">
      <thead class="sticky">
        <tr>
          <th class="th-sortable" data-sort="text"># <span class="sort-caret">↕</span></th>
          <th class="th-sortable" data-sort="date">Date <span class="sort-caret">↕</span></th>
          <th class="th-sortable" data-sort="text">System <span class="sort-caret">↕</span></th>
          <th class="th-sortable" data-sort="text">Logged By <span class="sort-caret">↕</span></th>
          <th class="th-sortable" data-sort="status">Status <span class="sort-caret">↕</span></th>
          <th class="text-end">Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for r in incidents %}
          <tr class="row-link {% if not r.complete %}table-warning{% endif %}"
              data-href="{{ url_for('record_view', kind='incident', rid=r.id) }}"
              data-status="{{ 'complete' if r.complete else 'pending' }}">
            <td class="fw-semibold">{{ r.number }}</td>
            <td data-value="{{ r.date }}">{{ r.date }}</td>
            <td>{{ r.system }}</td>
            <td>{{ r.logger }}</td>
            <td>
              {% if r.complete %}
                <span class="badge text-bg-success status-badge">Complete</span>
              {% else %}
                <span class="badge text-bg-light text-danger status-badge">Incomplete</span>
              {% endif %}
            </td>
            <td class="text-end">
              <a class="btn btn-light btn-sm" href="{{ url_for('record_view', kind='incident', rid=r.id) }}">View</a>
              <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('record_pdf', kind='incident', rid=r.id) }}">PDF</a>
              
{% if r.has_attachment %}
<a class="btn btn-outline-secondary btn-sm" href="{{ url_for('bundle_record_with_attachments', kind='incident', rid=r.id) }}">ZIP</a>
{% endif %}

{% if r.can_edit %}
<a class="btn btn-primary btn-sm" href="{{ url_for('edit_incident', rid=r.id) }}">Edit</a>
{% endif %}

              {% if session.get('role') == 'admin' %}
              <a class="btn btn-outline-danger btn-sm"
                 href="{{ url_for('request_delete_record', kind='incident', rid=r.id) }}">
                 Request Delete
              </a>
              {% endif %}
            </td>
          </tr>
        {% else %}
          <tr><td colspan="6" class="text-muted">No incidents found.</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
(function(){
  const table = document.getElementById('incTable');
  const tbody = table.tBodies[0];
  const rows  = Array.from(tbody.querySelectorAll('tr'));

  // Row click (ignore clicks on buttons/links/forms)
  tbody.addEventListener('click', (e) => {
    if (e.target.closest('a,button,form,input,select,textarea')) return;
    const tr = e.target.closest('tr.row-link');
    if (tr && tr.dataset.href) window.location = tr.dataset.href;
  });

  // Quick filter (client-side)
  document.querySelectorAll('[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      const f = btn.dataset.filter;
      rows.forEach(tr => {
        tr.hidden = (f !== 'all' && tr.dataset.status !== f);
      });
    });
  });

  // Sorting
  const getVal = (td, type, tr) => {
    if (type === 'status') return tr.dataset.status;
    return td.dataset.value || td.textContent.trim().toLowerCase();
  };
  const sortBy = (colIdx, type) => {
    const asc = !(table.dataset.sortCol == colIdx && table.dataset.sortDir === 'asc');
    const sorted = Array.from(tbody.querySelectorAll('tr'))
      .sort((a,b) => {
        const av = getVal(a.children[colIdx], type, a);
        const bv = getVal(b.children[colIdx], type, b);
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
    sorted.forEach(tr => tbody.appendChild(tr));
    table.dataset.sortCol = colIdx;
    table.dataset.sortDir = asc ? 'asc' : 'desc';
    // header state
    table.querySelectorAll('th').forEach((th,i)=>{
      th.classList.toggle('th-active', i===colIdx);
    });
  };
  table.querySelectorAll('th.th-sortable').forEach((th, i) => {
    th.addEventListener('click', () => sortBy(i, th.dataset.sort));
  });
})();
</script>
{% endblock %}
"""

USERS_HTML = """
{% extends "base.html" %}{% block body %}
<h5>Users</h5>

<div class="mb-3 d-flex gap-2">
  {% if session.get('role') == 'admin' %}{% endif %}
  {% if session.get('role') in ['admin','sd'] %}
    <a class="btn btn-primary btn-sm" href="{{ url_for('new_user') }}">New User</a>
    <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('reset_password') }}">Reset/Unlock</a>
  {% endif %}
</div>

<table class="table table-sm table-hover align-middle">
 <thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th class="text-end">Actions</th></tr></thead>
 <tbody>
 {% for u in users %}
  <tr>
    <td>{{ u.username }}</td>
    <td>{{ u.full_name }}</td>
    <td>{{ u.role }}</td>
    <td>
      {% if u.is_disabled %}<span class="badge text-bg-secondary">Disabled</span>{% else %}<span class="badge text-bg-success">Active</span>{% endif %}
      {% set ll = last_login.get(u.username) %}
      <div class="small text-muted mt-1">Last login: {{ ll.strftime('%Y-%m-%d %H:%M') ~ ' UTC' if ll else 'never' }}</div>
    </td>
    <td class="text-end">
      {% if session.get('role') in ['admin','sd'] %}
        <a class="btn btn-sm btn-outline-primary" href="{{ url_for('edit_user', user_id=u.id) }}">Edit</a>
        <form class="d-inline" method="post" action="{{ url_for('toggle_user', user_id=u.id) }}" autocomplete="off">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <button class="btn btn-sm btn-outline-warning">{{ 'Enable' if u.is_disabled else 'Disable' }}</button>
        </form>
        {% if session.get('role') == 'admin' %}
          <a class="btn btn-sm btn-outline-danger"
             href="{{ url_for('request_delete_user', user_id=u.id) }}">Request Delete</a>
        {% endif %}
      {% endif %}
    </td>
  </tr>
 {% else %}
   <tr><td colspan="5" class="text-muted">No users.</td></tr>
 {% endfor %}
 </tbody>
</table>
{% endblock %}
"""

PASSWORD_POLICY_HTML = """{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:760px">
  <h5 class="mb-3">Password Policy</h5>
  <div class="card card-soft p-3">
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="row g-3">
        <div class="col-md-6">
          <label class="form-label">Min length</label>
          <input class="form-control" name="min_length" value="{{ pol.min_length or 12 }}">
        </div>
        <div class="col-md-6">
          <label class="form-label">Expiry (days)</label>
          <input class="form-control" name="expiry_days" value="{{ pol.expiry_days or 0 }}">
          <div class="form-text">0 = never expire</div>
        </div>
        <div class="col-md-6">
          <label class="form-label">Lockout threshold</label>
          <input class="form-control" name="lockout_threshold" value="{{ pol.lockout_threshold or 3 }}">
        </div>
        <div class="col-md-6">
          <label class="form-label">Idle timeout (min)</label>
          <input class="form-control" name="idle_timeout_minutes" value="{{ pol.idle_timeout_minutes or 6 }}">
        </div>
        <div class="col-12">
          <div class="form-check form-check-inline">
            <input class="form-check-input" type="checkbox" name="require_upper" id="reqU" {% if pol.require_upper %}checked{% endif %}>
            <label class="form-check-label" for="reqU">Require uppercase</label>
          </div>
          <div class="form-check form-check-inline">
            <input class="form-check-input" type="checkbox" name="require_lower" id="reqL" {% if pol.require_lower %}checked{% endif %}>
            <label class="form-check-label" for="reqL">Require lowercase</label>
          </div>
          <div class="form-check form-check-inline">
            <input class="form-check-input" type="checkbox" name="require_number" id="reqN" {% if pol.require_number %}checked{% endif %}>
            <label class="form-check-label" for="reqN">Require number</label>
          </div>
          <div class="form-check form-check-inline">
            <input class="form-check-input" type="checkbox" name="require_special" id="reqS" {% if pol.require_special %}checked{% endif %}>
            <label class="form-check-label" for="reqS">Require special character</label>
          </div>
        </div>
        <div class="col-12">
          <button class="btn btn-primary">Save Policy</button>
          <a class="btn btn-outline-secondary" href="{{ url_for('view_users') }}">Back to Users</a>
        </div>
      </div>
    </form>
  </div>
</div>
{% endblock %}"""

USER_EDIT_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:720px">
  <h5 class="mb-3">Edit User — {{u.username}}</h5>
  <form method="post" enctype="multipart/form-data" autocomplete="off">
    {{ form.hidden_tag() }}
    <div class="row g-3">
      <div class="col-md-3">
        <label class="form-label">Title</label>
        {{ form.title(class="form-select") }}
      </div>
      <div class="col-md-4">
        <label class="form-label">First name</label>
        {{ form.first_name(class="form-control", autocomplete="off", autocapitalize="words") }}
      </div>
      <div class="col-md-5">
        <label class="form-label">Last name</label>
        {{ form.last_name(class="form-control", autocomplete="off", autocapitalize="words") }}
      </div>
      <div class="col-12">
        <label class="form-label">Username</label>
        {{ form.username(class="form-control", autocomplete="off", autocapitalize="none", spellcheck="false") }}
      </div>
    </div>
    <div class="mt-4 d-flex gap-2">
      <a href="{{ url_for('view_users') }}" class="btn btn-outline-secondary">Cancel</a>
      <button class="btn btn-primary">{{ form.submit.label.text }}</button>
    </div>
  </form>
</div>
{% endblock %}
"""

NEW_USER_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:720px">
  <h5 class="mb-3">Create User</h5>
  <form method="post" enctype="multipart/form-data" autocomplete="off">
    {{ form.hidden_tag() }}
    <div class="row g-3">
      <div class="col-md-3">{{ form.title.label }} {{ form.title(class="form-select", autocomplete="off") }}</div>
      <div class="col-md-4">{{ form.first_name.label }} {{ form.first_name(class="form-control", autocomplete="off", autocapitalize="words") }}</div>
      <div class="col-md-5">{{ form.last_name.label }} {{ form.last_name(class="form-control", autocomplete="off", autocapitalize="words") }}</div>
      <div class="col-md-6">{{ form.username.label }} {{ form.username(class="form-control", autocomplete="off", autocapitalize="none", spellcheck="false") }}</div>
      <div class="col-md-6">{{ form.role.label }} {{ form.role(class="form-select", autocomplete="off") }}</div>
      <div class="col-12">{{ form.password.label }} {{ form.password(class="form-control", autocomplete="off") }}</div>
      <div class="col-12 text-muted small">Password must be ≥12 chars, with at least 1 uppercase, 1 lowercase, and 1 special character.</div>
      {% if form.password.errors %}
        <div class="col-12 text-info small mt-1">
          {% for e in form.password.errors %}• {{ e }}<br>{% endfor %}
        </div>
      {% endif %}
    </div>
    <div class="mt-3"><button class="btn btn-primary">{{ form.submit.label.text }}</button></div>
  </form>
</div>
{% endblock %}
"""

RESET_PW_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:640px">
  <h5 class="mb-3">Reset / Unlock User</h5>
  <form method="post" enctype="multipart/form-data" autocomplete="off">
    {{ form.hidden_tag() }}
    <div class="mb-3">{{ form.username.label }} {{ form.username(class="form-control", autocomplete="off", autocapitalize="none", spellcheck="false") }}</div>
    <div class="mb-3">
      {{ form.new_password.label }} {{ form.new_password(class="form-control", autocomplete="off") }}
      {% if form.new_password.errors %}
        <div class="text-info small mt-1">
          Password does not meet password requirements:
          {% for e in form.new_password.errors %}<div>• {{ e }}</div>{% endfor %}
        </div>
      {% endif %}
    </div>
    <div class="text-muted small">Password must be ≥12 chars, with 1 uppercase, 1 lowercase, and 1 special character.</div>
    <button class="btn btn-primary mt-2">{{ form.submit.label.text }}</button>
  </form>
</div>
{% endblock %}
"""

CHANGE_PW_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:640px">
  <h5 class="mb-3">Change Password</h5>
  <form method="post" enctype="multipart/form-data" autocomplete="off">
    {{ form.hidden_tag() }}
    <div class="mb-3">{{ form.old_password.label }} {{ form.old_password(class="form-control", autocomplete="off") }}</div>
    <div class="mb-3">
      {{ form.new_password.label }} {{ form.new_password(class="form-control", autocomplete="off") }}
      {% if form.new_password.errors %}
        <div class="text-info small mt-1">
          Password does not meet password requirements:
          {% for e in form.new_password.errors %}<div>• {{ e }}</div>{% endfor %}
        </div>
      {% endif %}
    </div>
    <div class="mb-3">{{ form.confirm.label }} {{ form.confirm(class="form-control", autocomplete="off") }}</div>
    <div class="text-muted small">Password must be ≥12 chars, with 1 uppercase, 1 lowercase, and 1 special character.</div>
    <button class="btn btn-primary mt-2">{{ form.submit.label.text }}</button>
  </form>
</div>
{% endblock %}
"""

INCIDENT_NEW_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:860px">
  <h5 class="mb-3">New Incident</h5>
  <form method="post" enctype="multipart/form-data" autocomplete="off">
    {{ form.hidden_tag() }}
    <div class="row g-3">
      <div class="col-md-4">{{ form.date.label }} {{ form.date(class="form-control", autocomplete="off") }}</div>
      <div class="col-md-4">{{ form.incident_logger.label }} {{ form.incident_logger(class="form-control", autocomplete="off", readonly=True) }}</div>
      <div class="col-md-4">{{ form.channel_or_system.label }} {{ form.channel_or_system(class="form-select") }}</div>
      <div class="col-12">{{ form.incident.label }} {{ form.incident(class="form-control", rows=4, autocomplete="off") }}</div>

      <div class="col-md-6">
        {{ form.time_of_incident.label }}
        {{ form.time_of_incident(class="form-control", type="time", step="60", autocomplete="off") }}
      </div>
      <div class="col-md-6">
        {{ form.time_of_resolution.label }}
        {{ form.time_of_resolution(class="form-control", type="time", step="60", autocomplete="off") }}
      </div>


<div class="col-md-6">
  {{ form.date_of_resolution.label }}
  {{ form.date_of_resolution(class="form-control", autocomplete="off") }}
</div>

      <div class="col-12">{{ form.root_cause.label }} {{ form.root_cause(class="form-control", autocomplete="off") }}</div>
      <div class="col-12">{{ form.impact.label }} {{ form.impact(class="form-control", autocomplete="off") }}</div>
      <div class="col-12">{{ form.corrective_action.label }} {{ form.corrective_action(class="form-control", autocomplete="off") }}</div>

      <div class="col-md-6">{{ form.corrective_action_by.label }} {{ form.corrective_action_by(class="form-control", autocomplete="off") }}</div>
      <div class="col-md-6">{{ form.reviewer.label }} {{ form.reviewer(class="form-select", autocomplete="off") }}</div>
      <div class="col-12">
        <label class="form-label">Attachments</label>
        <input type="file" class="form-control" name="attachments" multiple>
        <div class="form-text">Optional. Up to 10 MB per file. Allowed: PDF only.</div>
      </div>
    </div>
    <div class="mt-3"><button class="btn btn-primary">{{ form.submit.label.text }}</button></div>
  </form>
</div>
{% endblock %}
"""



INCIDENT_EDIT_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:860px">
  <h5 class="mb-3">Edit Incident — {{ rec.number }}</h5>
  <div class="alert alert-info">You can edit until the assigned reviewer adds their comment. After that, editing is locked.</div>
  <form method="post" enctype="multipart/form-data" autocomplete="off">
    {{ form.hidden_tag() }}
    <div class="row g-3">
      <div class="col-md-4">{{ form.date.label }} {{ form.date(class="form-control", autocomplete="off") }}</div>
      <div class="col-md-4">{{ form.incident_logger.label }} {{ form.incident_logger(class="form-control", autocomplete="off", readonly=True) }}</div>
      <div class="col-md-4">{{ form.channel_or_system.label }} {{ form.channel_or_system(class="form-select") }}</div>
      <div class="col-12">{{ form.incident.label }} {{ form.incident(class="form-control", rows=4, autocomplete="off") }}</div>

      <div class="col-md-6">
        {{ form.time_of_incident.label }}
        {{ form.time_of_incident(class="form-control", type="time", step="60", autocomplete="off") }}
      </div>
      <div class="col-md-6">
        {{ form.time_of_resolution.label }}
        {{ form.time_of_resolution(class="form-control", type="time", step="60", autocomplete="off") }}
      </div>

      <div class="col-12">{{ form.root_cause.label }} {{ form.root_cause(class="form-control", autocomplete="off") }}</div>
      <div class="col-12">{{ form.impact.label }} {{ form.impact(class="form-control", autocomplete="off") }}</div>
      <div class="col-12">{{ form.corrective_action.label }} {{ form.corrective_action(class="form-control", autocomplete="off") }}</div>

      <div class="col-md-6">{{ form.corrective_action_by.label }} {{ form.corrective_action_by(class="form-control", autocomplete="off") }}</div>
      <div class="col-md-6">
        {{ form.reviewer.label }}
        {{ form.reviewer(class="form-select", autocomplete="off", disabled=True) }}
        <div class="form-text">Reviewer cannot be changed after creation.</div>
      </div>

      <div class="col-12">
        <label class="form-label">Add Attachments (optional)</label>
        <input type="file" class="form-control" name="attachments" multiple>
        
{% if attachments %}
<div class="col-12 mt-1">
  <label class="form-label">Existing Attachments</label>
  <ul class="list-group list-group-flush">
    {% for a in attachments %}
    <li class="list-group-item d-flex justify-content-between align-items-center">
      <div class="form-check">
        <input class="form-check-input me-2" type="checkbox" name="delete_attachment_ids" value="{{ a.id }}" id="del{{ a.id }}">
        <label class="form-check-label" for="del{{ a.id }}">{{ a.original_name }}</label>
      </div>
      <span class="btn-group">
        <a class="btn btn-sm btn-outline-primary" target="_blank" href="{{ url_for('preview_incident_attachment', rid=rec.id, aid=a.id) }}">Preview</a>
        <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('download_incident_attachment', rid=rec.id, aid=a.id) }}">Download</a>
      </span>
    </li>
    {% endfor %}
  </ul>
  <div class="form-text">Tick to remove selected files when you click Save.</div>
</div>
{% endif %}

<div class="mt-3">

      <button class="btn btn-primary">{{ form.submit.label.text }}</button>
      <a class="btn btn-outline-secondary ms-2" href="{{ url_for('record_view', kind='incident', rid=rec.id) }}">Cancel</a>
    </div>
  </form>
</div>
{% endblock %}
"""

# ===== GM view (shows IM/SDM inputs) =====
INCIDENT_GOV_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:980px">
  <h5 class="mb-3">Incident Governance — {{ rec.number }}</h5>

  <div class="mb-3 d-flex flex-wrap gap-2">
    <a class="btn btn-primary" href="{{ url_for('record_pdf', kind='incident', rid=rec.id) }}">Download PDF</a>
    {% if attachments %}
    <a class="btn btn-outline-secondary" href="{{ url_for('bundle_record_with_attachments', kind='incident', rid=rec.id) }}">Download PDF + Attachment (ZIP)</a>
    {% endif %}
  </div>

  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-3">Original Incident Details</h6>
    <div class="row g-3">
      <div class="col-md-3"><div class="label-sm">Number</div><div class="form-control-plaintext">{{ rec.number }}</div></div>

  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Attachments</h6>
    {% set attachments = attachments or [] %}
    {% if attachments %}
      <ul class="list-unstyled mb-0">
      {% for a in attachments %}
        <li class="mb-2">
          <i class="bi bi-paperclip me-1"></i>
          {{ a.original_name }}
          {% if a.size_bytes %}<span class="text-muted small">({{ (a.size_bytes/1024)|round(1) }} KB)</span>{% endif %}
          <div class="mt-1 d-flex gap-2">
            <a class="btn btn-sm btn-outline-primary" target="_blank" href="{{ url_for('preview_incident_attachment', rid=rec.id, aid=a.id) }}">Preview</a>
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('download_incident_attachment', rid=rec.id, aid=a.id) }}">Download</a>
          </div>
        </li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="text-muted small">No attachments.</div>
    {% endif %}
  </div>
      <div class="col-md-3"><div class="label-sm">Date</div><div class="form-control-plaintext">{{ rec.date or '' }}</div></div>
      <div class="col-md-6"><div class="label-sm">System / Channel</div><div class="form-control-plaintext">{{ rec.channel_or_system }}</div></div>
      <div class="col-12"><div class="label-sm">Incident</div><div class="readonly-block">{{ rec.incident }}</div></div>
      <div class="col-md-6"><div class="label-sm">Time of Incident</div><div class="form-control-plaintext">{{ rec.time_of_incident or '' }}</div></div>
      <div class="col-md-6"><div class="label-sm">Time of Resolution</div><div class="form-control-plaintext">{{ rec.time_of_resolution or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Root Cause</div><div class="readonly-block">{{ rec.root_cause or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Impact</div><div class="readonly-block">{{ rec.impact or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Corrective Action</div><div class="readonly-block">{{ rec.corrective_action or '' }}</div></div>
      <div class="col-md-4"><div class="label-sm">Corrective Action By</div><div class="form-control-plaintext">{{ rec.corrective_action_by or '' }}</div></div>
    </div>
  </div>

  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-3">Reviewer Input (IM/SDM)</h6>
    {% set has_im = (rec.im_comments or rec.im_signature) %}
    {% set has_sdm = (rec.sdm_comments or rec.sdm_signature) %}
    {% if not has_im and not has_sdm %}
      <div class="text-muted small">No IM/SDM inputs captured yet.</div>
    {% else %}
      <div class="row g-3">
        {% if has_im %}
          <div class="col-12"><div class="label-sm">IM Comment</div><div class="readonly-block">{{ rec.im_comments }}</div></div>
          <div class="col-md-6"><div class="label-sm">IM Signature</div><div class="form-control-plaintext">{{ rec.im_signature }}</div></div>
        {% endif %}
        {% if has_sdm %}
          <div class="col-12"><div class="label-sm">SDM Comment</div><div class="readonly-block">{{ rec.sdm_comments }}</div></div>
          <div class="col-md-6"><div class="label-sm">SDM Signature</div><div class="form-control-plaintext">{{ rec.sdm_signature }}</div></div>
        {% endif %}
      </div>
    {% endif %}
  </div>

  <div class="card card-soft p-3">
    <h6 class="mb-3">Governance</h6>
    {% if not gm_ready %}
      <div class="alert alert-info mb-3">Waiting for {{ (rec.reviewer or 'IM/SDM') }} to provide comment & signature before GM can comment.</div>
    {% endif %}
    <form method="post" enctype="multipart/form-data" autocomplete="off">
      {{ form.hidden_tag() }}
      <fieldset {% if not gm_ready %}disabled{% endif %}>
      <div class="mb-3">{{ form.governance_comments.label }} {{ form.governance_comments(class="form-control", rows=6, autocomplete="off") }}</div>
      <div class="mb-3">{{ form.governance_signature.label }} {{ form.governance_signature(class="form-control", readonly=True, autocomplete="off") }}</div>
      <button class="btn btn-primary">{{ form.submit.label.text }}</button>
      <a href="{{ url_for('records') }}" class="btn btn-outline-secondary ms-2">Back</a>
          </fieldset>
    </form>
  </div>
</div>
{% endblock %}
"""

# === IM & SDM review templates ===
INCIDENT_IM_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:980px">
  <h5 class="mb-3">IM Review — {{ rec.number }}</h5>

  <div class="mb-3 d-flex flex-wrap gap-2">
    <a class="btn btn-primary" href="{{ url_for('record_pdf', kind='incident', rid=rec.id) }}">Download PDF</a>
    {% if attachments %}
    <a class="btn btn-outline-secondary" href="{{ url_for('bundle_record_with_attachments', kind='incident', rid=rec.id) }}">Download PDF + Attachment (ZIP)</a>
    {% endif %}
  </div>

  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Original Incident Details</h6>
    <div class="row g-3">
      <div class="col-md-3"><div class="label-sm">Number</div><div class="form-control-plaintext">{{ rec.number }}</div></div>

  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Attachments</h6>
    {% set attachments = attachments or [] %}
    {% if attachments %}
      <ul class="list-unstyled mb-0">
      {% for a in attachments %}
        <li class="mb-2">
          <i class="bi bi-paperclip me-1"></i>
          {{ a.original_name }}
          {% if a.size_bytes %}<span class="text-muted small">({{ (a.size_bytes/1024)|round(1) }} KB)</span>{% endif %}
          <div class="mt-1 d-flex gap-2">
            <a class="btn btn-sm btn-outline-primary" target="_blank" href="{{ url_for('preview_incident_attachment', rid=rec.id, aid=a.id) }}">Preview</a>
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('download_incident_attachment', rid=rec.id, aid=a.id) }}">Download</a>
          </div>
        </li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="text-muted small">No attachments.</div>
    {% endif %}
  </div>
      <div class="col-md-3"><div class="label-sm">Date</div><div class="form-control-plaintext">{{ rec.date or '' }}</div></div>
      <div class="col-md-6"><div class="label-sm">System / Channel</div><div class="form-control-plaintext">{{ rec.channel_or_system }}</div></div>
      <div class="col-12"><div class="label-sm">Incident</div><div class="readonly-block">{{ rec.incident }}</div></div>
      <div class="col-md-6"><div class="label-sm">Time of Incident</div><div class="form-control-plaintext">{{ rec.time_of_incident or '' }}</div></div>
      <div class="col-md-6"><div class="label-sm">Time of Resolution</div><div class="form-control-plaintext">{{ rec.time_of_resolution or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Root Cause</div><div class="readonly-block">{{ rec.root_cause or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Impact</div><div class="readonly-block">{{ rec.impact }}</div></div>
      <div class="col-12"><div class="label-sm">Corrective Action</div><div class="readonly-block">{{ rec.corrective_action }}</div></div>
      <div class="col-md-4"><div class="label-sm">Corrective Action By</div><div class="form-control-plaintext">{{ rec.corrective_action_by or '' }}</div></div>
    </div>
  </div>

  {% if rec.sdm_comments or rec.sdm_signature %}
  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Existing SDM Input</h6>
    <div class="row g-3">
      {% if rec.sdm_comments %}<div class="col-12"><div class="label-sm">SDM Comment</div><div class="readonly-block">{{ rec.sdm_comments }}</div></div>{% endif %}
      {% if rec.sdm_signature %}<div class="col-md-6"><div class="label-sm">SDM Signature</div><div class="form-control-plaintext">{{ rec.sdm_signature }}</div></div>{% endif %}
    </div>
  </div>
  {% endif %}

  <div class="card card-soft p-3">
    <h6 class="mb-2">Your IM Review</h6>
    <form method="post" enctype="multipart/form-data" autocomplete="off">
      {{ form.hidden_tag() }}
      <div class="mb-3">{{ form.im_comments.label }} {{ form.im_comments(class="form-control", rows=6, autocomplete="off") }}</div>
      <div class="mb-3">{{ form.im_signature.label }} {{ form.im_signature(class="form-control", readonly=True, autocomplete="off") }}</div>
      <button class="btn btn-primary">{{ form.submit.label.text }}</button>
      <a href="{{ url_for('records') }}" class="btn btn-outline-secondary ms-2">Back</a>
    </form>
  </div>
</div>
{% endblock %}
"""

INCIDENT_SDM_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:980px">
  <h5 class="mb-3">SDM Review — {{ rec.number }}</h5>

  <div class="mb-3 d-flex flex-wrap gap-2">
    <a class="btn btn-primary" href="{{ url_for('record_pdf', kind='incident', rid=rec.id) }}">Download PDF</a>
    {% if attachments %}
    <a class="btn btn-outline-secondary" href="{{ url_for('bundle_record_with_attachments', kind='incident', rid=rec.id) }}">Download PDF + Attachment (ZIP)</a>
    {% endif %}
  </div>

  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Original Incident Details</h6>
    <div class="row g-3">
      <div class="col-md-3"><div class="label-sm">Number</div><div class="form-control-plaintext">{{ rec.number }}</div></div>

  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Attachments</h6>
    {% set attachments = attachments or [] %}
    {% if attachments %}
      <ul class="list-unstyled mb-0">
      {% for a in attachments %}
        <li class="mb-2">
          <i class="bi bi-paperclip me-1"></i>
          {{ a.original_name }}
          {% if a.size_bytes %}<span class="text-muted small">({{ (a.size_bytes/1024)|round(1) }} KB)</span>{% endif %}
          <div class="mt-1 d-flex gap-2">
            <a class="btn btn-sm btn-outline-primary" target="_blank" href="{{ url_for('preview_incident_attachment', rid=rec.id, aid=a.id) }}">Preview</a>
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('download_incident_attachment', rid=rec.id, aid=a.id) }}">Download</a>
          </div>
        </li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="text-muted small">No attachments.</div>
    {% endif %}
  </div>
      <div class="col-md-3"><div class="label-sm">Date</div><div class="form-control-plaintext">{{ rec.date or '' }}</div></div>
      <div class="col-md-6"><div class="label-sm">System / Channel</div><div class="form-control-plaintext">{{ rec.channel_or_system }}</div></div>
      <div class="col-12"><div class="label-sm">Incident</div><div class="readonly-block">{{ rec.incident }}</div></div>
      <div class="col-md-6"><div class="label-sm">Time of Incident</div><div class="form-control-plaintext">{{ rec.time_of_incident or '' }}</div></div>
      <div class="col-md-6"><div class="label-sm">Time of Resolution</div><div class="form-control-plaintext">{{ rec.time_of_resolution or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Root Cause</div><div class="readonly-block">{{ rec.root_cause or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Impact</div><div class="readonly-block">{{ rec.impact or '' }}</div></div>
      <div class="col-12"><div class="label-sm">Corrective Action</div><div class="readonly-block">{{ rec.corrective_action or '' }}</div></div>
      <div class="col-md-4"><div class="label-sm">Corrective Action By</div><div class="form-control-plaintext">{{ rec.corrective_action_by or '' }}</div></div>
    </div>
  </div>

  {% if rec.im_comments or rec.im_signature %}
  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Existing IM Input</h6>
    <div class="row g-3">
      {% if rec.im_comments %}<div class="col-12"><div class="label-sm">IM Comment</div><div class="readonly-block">{{ rec.im_comments }}</div></div>{% endif %}
      {% if rec.im_signature %}<div class="col-md-6"><div class="label-sm">IM Signature</div><div class="form-control-plaintext">{{ rec.im_signature }}</div></div>{% endif %}
    </div>
  </div>
  {% endif %}

  <div class="card card-soft p-3">
    <h6 class="mb-2">Your SDM Review</h6>
    <form method="post" enctype="multipart/form-data" autocomplete="off">
      {{ form.hidden_tag() }}
      <div class="mb-3">{{ form.sdm_comments.label }} {{ form.sdm_comments(class="form-control", rows=6, autocomplete="off") }}</div>
      <div class="mb-3">{{ form.sdm_signature.label }} {{ form.sdm_signature(class="form-control", readonly=True, autocomplete="off") }}</div>
      <button class="btn btn-primary">{{ form.submit.label.text }}</button>
      <a href="{{ url_for('records') }}" class="btn btn-outline-secondary ms-2">Back</a>
    </form>
  </div>
</div>
{% endblock %}
"""

AUDIT_HTML = """
{% extends "base.html" %}{% block body %}
<h5>Audit Log</h5>
<form class="row g-2 mb-3" method="get" autocomplete="off">
  <div class="col-sm-4"><input name="q" value="{{ request.args.get('q','') }}" class="form-control" placeholder="Keyword (e.g., delete)" autocomplete="off"></div>
  <div class="col-sm-3"><input name="from" value="{{ request.args.get('from','') }}" class="form-control" placeholder="From (YYYY-MM-DD)" autocomplete="off"></div>
  <div class="col-sm-3"><input name="to" value="{{ request.args.get('to','') }}" class="form-control" placeholder="To (YYYY-MM-DD)" autocomplete="off"></div>
  <div class="col-sm-2 d-grid d-sm-flex gap-2"><button class="btn btn-primary">Filter</button><a class="btn btn-outline-secondary" href="{{ url_for('records') }}">Clear</a></div>
</form>

<div class="card card-soft p-3">
<table class="table table-sm table-hover">
  <thead><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Entity</th><th>ID</th><th>Details</th></tr></thead>
  <tbody>
  {% for a in rows %}
    <tr>
      <td class="text-muted small">{{ a.timestamp }}</td>
      <td>{{ a.username }}</td>
      <td>{{ a.action }}</td>
      <td>{{ a.entity_type }}</td>
      <td>{{ a.entity_id or '' }}</td>
      <td>{{ a.details }}</td>
    </tr>
  {% else %}
    <tr><td colspan="6" class="text-muted">No audit entries.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>
{% endblock %}
"""

ALERTS_HTML = """
{% extends "base.html" %}{% block body %}
<h5 class="mb-3">Alerts</h5>
<div class="card card-soft p-3">
  <table class="table table-sm table-hover align-middle mb-0">
    <thead><tr><th>Type</th><th>Number</th><th>Date</th><th>System</th><th>Action</th><th class="text-end"></th></tr></thead>
    <tbody>
    {% for it in items %}
      <tr>
        <td class="text-capitalize">{{ it.kind }}</td>
        <td>{{ it.number }}</td>
        <td>{{ it.date }}</td>
        <td>{{ it.system }}</td>
        <td>{{ it.action }}</td>
        <td class="text-end"><a class="btn btn-sm btn-outline-primary" href="{{ it.link }}">Open</a></td>
      </tr>
    {% else %}
      <tr><td colspan="6" class="text-muted">No alerts 🎉</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

# --- NEW: Delete request templates ---
DELETE_REQUEST_FORM_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:720px">
  <h5 class="mb-3">Request Delete — {{ entity_label }}</h5>
  <div class="alert alert-warning">
    This action requires approval by a <strong>Governance Manager (GM)</strong> before anything is removed.
  </div>
  <form method="post" enctype="multipart/form-data" autocomplete="off">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <div class="mb-3">
      <label class="form-label">Record</label>
      <div class="form-control-plaintext">{{ entity_label }}</div>
    </div>
    <div class="mb-3">
      <label class="form-label">Reason</label>
      <textarea name="reason" class="form-control" rows="5" required></textarea>
    </div>
    <button class="btn btn-primary">Submit Request</button>
    <a href="{{ back_url }}" class="btn btn-outline-secondary ms-2">Cancel</a>
  </form>
</div>
{% endblock %}
"""

DELETE_REQUESTS_LIST_HTML = """
{% extends "base.html" %}{% block body %}
<h5 class="mb-3">Delete Requests (GM Approval)</h5>
<div class="card card-soft p-3">
  <table class="table table-sm table-hover align-middle mb-0">
    <thead><tr><th>When (UTC)</th><th>Requested By</th><th>Record</th><th>Reason</th><th class="text-end">Actions</th></tr></thead>
    <tbody>
    {% for r in rows %}
      <tr>
        <td class="text-muted small">{{ r.created_at }}</td>
        <td>{{ r.requested_by }}</td>
        <td>{{ r.entity_label }}</td>
        <td style="max-width:480px">{{ r.reason }}</td>
        <td class="text-end">
          <form class="d-inline" method="post" action="{{ url_for('approve_delete_request', drid=r.id) }}" autocomplete="off">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="btn btn-sm btn-outline-danger">Approve & Delete</button>
          </form>
          <form class="d-inline" method="post" action="{{ url_for('reject_delete_request', drid=r.id) }}" autocomplete="off">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="btn btn-sm btn-outline-secondary">Reject</button>
          </form>
        </td>
      </tr>
    {% else %}
      <tr><td colspan="5" class="text-muted">No pending requests.</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

PDF_EXEC_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page { size: A4; margin: 24mm 18mm 20mm 18mm; }
  body { font-family: Helvetica, Arial, sans-serif; font-size: 10.5pt; color: #111; }
  .header { border-bottom: 2px solid #0d6efd; padding-bottom: 6px; margin-bottom: 14px; }
  .brand { font-size: 11pt; color:#6c757d; letter-spacing:.2px; }
  h1 { font-size: 16pt; margin: 2px 0 4px 0; }
  .meta { font-size: 9pt; color:#6c757d; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 8px 10px; vertical-align: top; }
  th { text-align: left; width: 32%; }
  tr { border-bottom: 1px solid #e9ecef; }
  tr:nth-child(even) td { background: #fafbfc; }
  .footer { margin-top: 14px; padding-top: 8px; border-top: 1px dashed #ced4da; font-size: 9pt; color:#6c757d; }
</style>
</head>
<body>
  <div class="header">
    <div class="brand">{{ brand }}</div>
    <h1>{{ title }}</h1>
    <div class="meta">Generated {{ now }}</div>
  </div>

  <table>
    {% for label, val in rows %}
      <tr>
        <th>{{ label }}</th>
        <td>{{ (val or '') | e }}</td>
      </tr>
    {% endfor %}
  </table>

  <div class="footer">
    Confidential — For internal use only. • Page <pdf:pagenumber/> of <pdf:pagecount/>
  </div>
</body>
</html>
"""



SETTINGS_HTML = """{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:820px">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h5 class="mb-0">Settings</h5>
</div>

  <!-- Systems management -->
  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Systems / Channels</h6>
    <form method="post" class="row g-2" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <input type="hidden" name="section" value="systems">
      <div class="col-md-6">
        <label class="form-label">Add System</label>
        <input name="name" class="form-control" placeholder="e.g., USSD" required autocomplete="off">
      </div>
      <div class="col-md-2 d-grid align-items-end">
        <button class="btn btn-primary mt-4">Add</button>
      </div>
    </form>
  </div>
  <div class="card card-soft p-3 mb-3">
    <h6 class="mb-2">Existing</h6>
    <table class="table table-sm table-hover align-middle mb-0">
      <thead><tr><th>Name</th><th>Status</th><th class="text-end">Actions</th></tr></thead>
      <tbody>
        {% for s in systems %}
          <tr>
            <td>{{ s.name }}</td>
            <td>
              {% if s.active %}<span class="badge text-bg-success">Active</span>
              {% else %}<span class="badge text-bg-secondary">Inactive</span>{% endif %}
            </td>
            <td class="text-end">
              <form method="post" action="{{ url_for('toggle_system', sid=s.id) }}" class="d-inline">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-sm btn-outline-warning">{{ 'Disable' if s.active else 'Enable' }}</button>
              </form>
              <form method="post" action="{{ url_for('delete_system', sid=s.id) }}" class="d-inline" onsubmit="return confirm('Delete this system?');">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="btn btn-sm btn-outline-danger">Delete</button>
              </form>
            </td>
          </tr>
        {% else %}
          <tr><td colspan="3" class="text-muted">No systems yet.</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Password policy editor -->
  <div class="card card-soft p-3">
    <h6 class="mb-2">Password Policy</h6>
    <form method="post" class="row g-3" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <input type="hidden" name="section" value="policy">
      <div class="col-sm-3">
        <label class="form-label">Min length</label>
        <input type="number" min="6" name="min_length" class="form-control" value="{{ pol.min_length }}">
      </div>
      <div class="col-sm-3">
        <label class="form-label">Expiry (days)</label>
        <input type="number" min="0" name="expiry_days" class="form-control" value="{{ pol.expiry_days }}">
        <div class="form-text">0 = never expire</div>
      </div>
      <div class="col-sm-3">
        <label class="form-label">Lockout threshold</label>
        <input type="number" min="1" name="lockout_threshold" class="form-control" value="{{ pol.lockout_threshold }}">
      </div>
      <div class="col-sm-3">
        <label class="form-label">Idle timeout (min)</label>
        <input type="number" min="1" name="idle_timeout_minutes" class="form-control" value="{{ pol.idle_timeout_minutes }}">
      </div>
      <div class="col-12">
        <div class="form-check form-check-inline">
          <input class="form-check-input" type="checkbox" name="require_upper" id="reqU" {% if pol.require_upper %}checked{% endif %}>
          <label class="form-check-label" for="reqU">Require uppercase</label>
        </div>
        <div class="form-check form-check-inline">
          <input class="form-check-input" type="checkbox" name="require_lower" id="reqL" {% if pol.require_lower %}checked{% endif %}>
          <label class="form-check-label" for="reqL">Require lowercase</label>
        </div>
        <div class="form-check form-check-inline">
          <input class="form-check-input" type="checkbox" name="require_number" id="reqN" {% if pol.require_number %}checked{% endif %}>
          <label class="form-check-label" for="reqN">Require number</label>
        </div>
        <div class="form-check form-check-inline">
          <input class="form-check-input" type="checkbox" name="require_special" id="reqS" {% if pol.require_special %}checked{% endif %}>
          <label class="form-check-label" for="reqS">Require special character</label>
        </div>
      </div>
      <div class="col-12">
        <button class="btn btn-primary">Save Policy</button>
      </div>
    </form>
  </div>
</div>
{% endblock %}"""


RECORD_VIEW_HTML = """
{% extends "base.html" %}{% block body %}
<div class="card shadow-sm mb-3">
  <div class="card-body d-flex flex-wrap justify-content-between align-items-center">
    <div>
      <div class="text-muted small">{{ kind|capitalize }}</div>
      
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
:root{
  --exec-bg:#f6f7fb;
  --exec-card:#ffffff;
  --exec-border:#e9edf3;
  --exec-text:#0f172a;
  --exec-muted:#6b7280;
  --exec-shadow:0 10px 30px rgba(15,23,42,.08);
}
html,body{background:var(--exec-bg) !important;color:var(--exec-text);font-family:"Inter",system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif;}
.card-soft{background:var(--exec-card);border:1px solid var(--exec-border);border-radius:20px;box-shadow:var(--exec-shadow);}
.sys-card{background:var(--exec-card);border-radius:16px;border-left:6px solid #e5e7eb;box-shadow:0 6px 18px rgba(15,23,42,.06);}
.sys-chip{display:flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:999px;color:#fff;font-weight:700;}
.table>tbody>tr>th{width:28%;color:#111827;}
.table>tbody>tr>td{color:#374151;}
pre{white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;font-size:.95rem;}
.badge.bg-danger{background:#ef4444!important}
.badge.bg-success{background:#10b981!important}
.btn-primary{background:#1363df;border-color:#1363df}
.btn-outline-secondary{border-color:#d0d7e2;color:#374151}
.sys-card:hover{transform:translateY(-2px);transition:.2s ease;box-shadow:0 12px 24px rgba(15,23,42,.12);}
</style>

<h4 class="mb-0">{{ number }}</h4>
    </div>
    <div class="d-flex gap-2 align-items-center">
      <span class="badge {% if complete %}bg-success{% else %}bg-danger{% endif %}">{{ 'Complete' if complete else 'Requires Action' }}</span>
      <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('records') }}">Back</a>
      <a class="btn btn-primary btn-sm" href="{{ url_for('record_pdf', kind=kind, rid=rid) }}">Download PDF</a>
      <button class="btn btn-outline-dark btn-sm" onclick="window.print()">Print</button>
    </div>
  </div>
  <div class="card-footer bg-light">
    <div class="d-flex flex-wrap gap-3">
      <div><strong>Date:</strong> {{ date }}</div>
      <div><strong>System:</strong> {{ system }}</div>
      {% if logger %}<div><strong>Logged By:</strong> {{ logger }}</div>{% endif %}
    </div>
  </div>
</div>

<div class="row g-3">
  <div class="col-lg-7">
    <div class="card shadow-sm">
      <div class="card-header">Executive Summary</div>
      <div class="card-body">
        <table class="table table-sm table-borderless mb-0">
          {% for label, val in rows %}
            {% if label in ['Incident Narrative','Narrative','Impact','Root Cause','Corrective Action','Correction Taken'] %}
              <tr><th style="width:28%">{{ label }}</th><td><pre class="mb-0">{{ val }}</pre></td></tr>
            {% endif %}
          {% endfor %}
        </table>
      </div>
    </div>
    <div class="card shadow-sm mt-3">
      <div class="card-header">Details</div>
      <div class="card-body">
        <table class="table table-sm mb-0">
          {% for label, val in rows %}
            {% if label not in ['Incident Narrative','Narrative','Impact','Root Cause','Corrective Action','Correction Taken'] %}
              <tr><th style="width:28%">{{ label }}</th><td>{{ val }}</td></tr>
            {% endif %}
          {% endfor %}
        </table>
      </div>
    </div>
  </div>
  <div class="col-lg-5">
    <div class="card shadow-sm">
      <div class="card-header">Status</div>
      <div class="card-body">
        <div class="d-flex align-items-center gap-2 mb-2">
          <span class="badge {% if complete %}bg-success{% else %}bg-danger blink{% endif %}">{{ 'Complete' if complete else 'Requires Action' }}</span>
        </div>
        {% if pending_banner %}
          <div class="alert alert-warning py-2 px-3 mb-0">{{ pending_banner }}</div>
        {% endif %}
      </div>
    </div>
    <div class="card shadow-sm mt-3">

<div class="card shadow-sm mt-3">
  <div class="card-header">Attachments</div>
  <div class="card-body">
    {% if attachments %}
      <ul class="list-group list-group-flush">
      {% for a in attachments %}
        <li class="list-group-item d-flex justify-content-between align-items-center">
          <span>{{ a.original_name }}</span>
          <span class="btn-group">
            <a class="btn btn-sm btn-outline-primary" target="_blank" href="{{ url_for('preview_incident_attachment', rid=rid, aid=a.id) }}">Preview</a>
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('download_incident_attachment', rid=rid, aid=a.id) }}">Download</a>
          </span>
        </li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="text-muted">No attachments</div>
    {% endif %}
  </div>
</div>
      <div class="card-header">Quick Links</div>
      <div class="card-body d-grid gap-2">
        <a class="btn btn-primary" href="{{ url_for('record_pdf', kind=kind, rid=rid) }}">Download PDF</a>
        {% if can_edit %}
        <a class="btn btn-primary" href="{{ url_for('edit_incident', rid=rid) }}">Edit Incident</a>
        {% endif %}
        {% if attachments %}
        <a class="btn btn-outline-secondary" href="{{ url_for('bundle_record_with_attachments', kind=kind, rid=rid) }}">Download PDF + Attachment (ZIP)</a>
        {% endif %}
        <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('records') }}">Back to Records</a>
      </div>
    </div>
    </div>
  </div>
</div>
{% endblock %}
"""

# Register templates


BACKUP_HTML = r'''{% extends 'base.html' %}
{% block body %}
<div class="container py-3" style="max-width: 900px;">
  <h3 class="mb-3">Backup</h3>

  <form method="post" action="{{ url_for('create_backup') }}" class="mb-3">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button class="btn btn-primary">Create &amp; Download Backup (.zip)</button>
  </form>

  {% if files %}
  <div class="card">
    <div class="card-header">Previous backups</div>
    <ul class="list-group list-group-flush">
      {% for f in files %}
      <li class="list-group-item d-flex justify-content-between align-items-center">
        <span>{{ f }}</span>
        <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('download_backup', filename=f) }}">Download</a>
      </li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}
</div>
{% endblock %}'''



ADMIN_HEALTH_HTML = """
{% extends "base.html" %}{% block body %}
<div class="container" style="max-width:1000px">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h5 class="mb-0">Admin Health</h5>
    <div>
      <a class="btn btn-sm btn-primary" href="{{ url_for('admin_health', refresh=1) }}">Recompute now</a>
    </div>
  </div>

  <div class="row g-3">
    <div class="col-md-4">
      <div class="card shadow-sm h-100">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-center">
            <h6 class="mb-0">Database</h6>
            {% set ok = data.metrics.db_ok %}
            <span class="badge {{ 'text-bg-success' if ok else 'text-bg-danger' }}">{{ 'OK' if ok else 'Down' }}</span>
          </div>
          <hr class="my-2"/>
          <div class="small text-muted">Dialect</div>
          <div>{{ data.metrics.db_dialect or '—' }}</div>
          <div class="small text-muted mt-2">Path</div>
          <div class="text-truncate" title="{{ data.metrics.db_file_path or data.metrics.db_uri }}">{{ data.metrics.db_file_path or data.metrics.db_uri or '—' }}</div>
          <div class="small text-muted mt-2">Size</div>
          <div>
            {% set fs = (data.metrics.db_file_size_bytes or 0) / (1024*1024) %}
            {% set es = (data.metrics.db_size_bytes_estimated or 0) / (1024*1024) %}
            {{ '%.1f'|format(fs) }} MB file
            {% if es %}<span class="text-muted"> (est. live {{ '%.1f'|format(es) }} MB)</span>{% endif %}
          </div>
        </div>
      </div>
    </div>

    <div class="col-md-4">
      <div class="card shadow-sm h-100">
        <div class="card-body">
          <h6 class="mb-2">Counts</h6>
          <div class="d-flex justify-content-between"><span>Users</span><span>{{ data.metrics.users }}</span></div>
          <div class="d-flex justify-content-between"><span>Incidents</span><span>{{ data.metrics.incidents_total }}</span></div>
          <div class="d-flex justify-content-between"><span>Attachments</span><span>{{ data.metrics.attachments_total }}</span></div>
          <hr class="my-2"/>
          <div class="d-flex justify-content-between small"><span>Pending IM</span><span>{{ data.metrics.incidents_pending_im }}</span></div>
          <div class="d-flex justify-content-between small"><span>Pending SDM</span><span>{{ data.metrics.incidents_pending_sdm }}</span></div>
          <div class="d-flex justify-content-between small"><span>Pending GM</span><span>{{ data.metrics.incidents_pending_gm }}</span></div>
        </div>
      </div>
    </div>

    <div class="col-md-4">
      <div class="card shadow-sm h-100">
        <div class="card-body">
          <h6 class="mb-2">Process & Disk</h6>
          <div class="d-flex justify-content-between"><span>PID</span><span>{{ data.metrics.pid }}</span></div>
          <div class="d-flex justify-content-between"><span>Python</span><span>{{ data.metrics.python_version }}</span></div>
          <div class="d-flex justify-content-between"><span>Uptime</span><span>{{ ((now - data.started_at).total_seconds() // 60)|int }} min</span></div>
          <hr class="my-2"/>
          <div class="d-flex justify-content-between"><span>Disk Free</span><span>{{ data.metrics.disk_free_mb }} MB</span></div>
          <div class="d-flex justify-content-between"><span>Disk Total</span><span>{{ data.metrics.disk_total_mb }} MB</span></div>
          <div class="d-flex justify-content-between"><span>Last Run</span><span>{{ data.last_run.strftime('%Y-%m-%d %H:%M:%S') if data.last_run else '—' }}</span></div>
        </div>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""
app.jinja_loader = DictLoader({
    'backup.html': BACKUP_HTML,
    'base.html': BASE_HTML,
    'login.html': LOGIN_HTML,
    'index.html': INDEX_HTML,
    'records.html': RECORDS_HTML,
    'users.html': USERS_HTML,
    'user_edit.html': USER_EDIT_HTML,
    'new_user.html': NEW_USER_HTML,
    'reset_pw.html': RESET_PW_HTML,
    'change_pw.html': CHANGE_PW_HTML,
    'incident_new.html': INCIDENT_NEW_HTML,
    'incident_edit.html': INCIDENT_EDIT_HTML,
    'incident_gov.html': INCIDENT_GOV_HTML,
    'incident_im.html': INCIDENT_IM_HTML,
    'incident_sdm.html': INCIDENT_SDM_HTML,
    'audit.html': AUDIT_HTML,
    'alerts.html': ALERTS_HTML,
    'admin_health.html': ADMIN_HEALTH_HTML,
    'pdf_exec.html': PDF_EXEC_HTML,
    'record_view.html': RECORD_VIEW_HTML,
    'settings.html': SETTINGS_HTML,
    'password_policy.html': PASSWORD_POLICY_HTML,
    # NEW:
    'delete_request_form.html': DELETE_REQUEST_FORM_HTML,
    'delete_requests_list.html': DELETE_REQUESTS_LIST_HTML,
})

# -------------------------
# Startup: create DB, auto-migrations, seed admin (secure)
# -------------------------
def _has_column(table, col):
    rows = db.session.execute(db.text(f"PRAGMA table_info('{table}')")).mappings().all()
    return any(r["name"] == col for r in rows)

def _add_column(table, col, ddl, set_default_sql=None):
    if not _has_column(table, col):
        db.session.execute(db.text(f'ALTER TABLE "{table}" ADD COLUMN {col} {ddl}'))
        if set_default_sql:
            db.session.execute(db.text(set_default_sql))
        db.session.commit()


with app.app_context():
    db.create_all()
    # Ensure IncidentAttachment table and all columns exist (simple, SQLite-safe migrations)
    _add_column('incident_attachment', 'incident_id', 'INTEGER')
    _add_column('incident_attachment', 'original_name', 'VARCHAR(255)')

    _add_column('incident_attachment', 'stored_name', 'VARCHAR(255)',
            'UPDATE incident_attachment SET stored_name=COALESCE(stored_name, original_name) WHERE stored_name IS NULL OR stored_name=""')

    _add_column('incident_attachment', 'stored_path', 'VARCHAR(512)')
    _add_column('incident_attachment', 'content_type', 'VARCHAR(120)')
    _add_column('incident_attachment', 'size_bytes', 'INTEGER')
    _add_column('incident_attachment', 'uploaded_by', 'VARCHAR(64)')
    _add_column('incident_attachment', 'uploaded_at', 'DATETIME')
    # Existing user safety columns
    _add_column('user', 'created_at', 'DATETIME',
                'UPDATE "user" SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL')
    _add_column('user', 'failed_attempts', 'INTEGER',
                'UPDATE "user" SET failed_attempts=0 WHERE failed_attempts IS NULL')
    _add_column('user', 'force_password_change', 'BOOLEAN',
                'UPDATE "user" SET force_password_change=0 WHERE force_password_change IS NULL')
    _add_column('user', 'is_disabled', 'BOOLEAN',
                'UPDATE "user" SET is_disabled=0 WHERE is_disabled IS NULL')
    _add_column('user', 'password_changed_at', 'DATETIME',
                'UPDATE "user" SET password_changed_at=CURRENT_TIMESTAMP WHERE password_changed_at IS NULL')

    # Reviewer column + IM/SDM review columns
    _add_column('incident', 'reviewer', 'VARCHAR(8)')
    _add_column('incident', 'im_comments', 'TEXT')
    _add_column('incident', 'im_signature', 'VARCHAR(128)')
    _add_column('incident', 'sdm_comments', 'TEXT')
    _add_column('incident', 'sdm_signature', 'VARCHAR(128)')
    _add_column('incident', 'date_of_resolution', 'DATE')  # NEW

    # Ensure password policy row exists and apply idle timeout
    db.create_all()
    pol = PasswordPolicy.query.get(1)
    if not pol:
        pol = PasswordPolicy(id=1)
        db.session.add(pol)
        db.session.commit()
    # Update app idle timeout dynamically
    try:
        app.permanent_session_lifetime = timedelta(minutes=int(pol.idle_timeout_minutes or 6))
    except Exception:
        pass

    if not User.query.filter_by(username='admin').first():
        seed_pw = os.environ.get('ADMIN_SEED_PASSWORD')
        if not seed_pw:
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}"
            seed_pw = ''.join(secrets.choice(alphabet) for _ in range(20))
            print(f"[SETUP] Admin temp password (set ADMIN_SEED_PASSWORD to control): {seed_pw}")
        u = User(username='admin', role='admin', first_name='System', last_name='Admin', force_password_change=True)
        u.set_password(seed_pw)
        db.session.add(u)
        db.session.commit()


# -------------------------
# Pre-request: force password change gate
# -------------------------

@app.before_request
def _rbac_seed_once():
    # Seed privileges/roles if not present
    try:
        # Quick existence check
        if Privilege.query.count() == 0 or Role.query.count() == 0:
            ensure_privileges_and_roles()
    except Exception as _:
        pass

@app.before_request
def enforce_password_change():
    allowed = {'login', 'change_password', 'static'}
    if session.get('user_id') and request.endpoint not in allowed:
        u = db.session.get(User, session['user_id'])
        if u and u.force_password_change:
            if request.endpoint != 'change_password':
                flash('Please change your password to continue.', 'warning')
                return redirect(url_for('change_password'))

# -------------------------
# Auth
# -------------------------
def _is_safe_next(target):
    if not target:
        return False
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return (test.scheme in ('http', 'https')) and (ref.netloc == test.netloc) and test.path.startswith('/')

@limiter.limit("10/minute;100/hour")
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = User.query.filter_by(username=form.username.data.strip()).first()
        pol = _get_policy()
        if not u or not u.check_password(form.password.data):
            if u:
                u.failed_attempts += 1
                threshold = int(pol.lockout_threshold or 3)
                if u.failed_attempts >= threshold:
                    u.is_disabled = True
                    log_audit('LOCK', 'User', u.id, f'User {u.username} locked after 3 failed logins')
                db.session.commit()
            flash('Invalid credentials.', 'danger')
            return render_template('login.html', form=form, title='Login')
        if u.is_disabled:
            flash('Account is disabled. Ask an admin to unlock.', 'warning')
            return render_template('login.html', form=form, title='Login')
        session.clear()
        session.permanent = True
        session['user_id'] = u.id
        session['username'] = u.username
        session['role'] = u.role
        session['last_seen'] = datetime.now(timezone.utc).timestamp()
        u.failed_attempts = 0
        db.session.commit()
        log_audit('LOGIN', 'User', u.id, f"{u.username} logged in")
        nxt = request.args.get('next')
        return redirect(nxt) if _is_safe_next(nxt) else redirect(url_for('index'))
    return render_template('login.html', form=form, title='Login')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/users/change-password', methods=['GET','POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    # Apply dynamic validators
    form.new_password.validators = [DataRequired()] + _build_password_validators()
    if request.method == 'POST':
        if form.validate():
            u = db.session.get(User, session['user_id'])
            if not u.check_password(form.old_password.data):
                flash('Current password incorrect.', 'danger')
            else:
                u.set_password(form.new_password.data)
                u.password_changed_at = datetime.now(timezone.utc)
                u.force_password_change = False
                db.session.commit()
                log_audit('UPDATE', 'User', u.id, f"{current_username()} changed own password")
                flash('Password updated.', 'success')
                return redirect(url_for('index'))
        else:
            if form.new_password.errors:
                flash('Password does not meet password requirements (min 12 chars, 1 uppercase, 1 lowercase, 1 special character).', 'info')
    return render_template('change_pw.html', form=form, title='Change Password')

# -------------------------
# Alerts: global badge count (GM/IM/SDM)
# -------------------------
@app.context_processor
def inject_alert_count():
    count = 0
    role = session.get('role')
    if session.get('user_id') and role in ['gm','im','sdm']:
        if role == 'gm':
            # GM pending governance items
            count = Incident.query.filter(
                db.or_(Incident.governance_comments.is_(None), db.func.trim(Incident.governance_comments) == '')
            ).count()
            # NEW: pending delete requests
            count += DeleteRequest.query.filter_by(status='pending').count()
        elif role == 'im':
            count = Incident.query.filter(
                db.func.upper(db.func.coalesce(Incident.reviewer, '')) == 'IM',
                db.or_(
                    Incident.im_comments.is_(None), db.func.trim(Incident.im_comments) == '',
                    Incident.im_signature.is_(None), db.func.trim(Incident.im_signature) == ''
                )
            ).count()
        elif role == 'sdm':
            count = Incident.query.filter(
                db.func.upper(db.func.coalesce(Incident.reviewer, '')) == 'SDM',
                db.or_(
                    Incident.sdm_comments.is_(None), db.func.trim(Incident.sdm_comments) == '',
                    Incident.sdm_signature.is_(None), db.func.trim(Incident.sdm_signature) == ''
                )
            ).count()
    return dict(alert_count=count)

# -------------------------
# Executive Dashboard route (updated)
# -------------------------
@app.route('/')
@login_required
def index():
    # Top systems (case-insensitive)
    inc_rows_raw = db.session.execute(db.text("""
        SELECT LOWER(TRIM(COALESCE(channel_or_system,''))) AS system_key,
               COUNT(*) AS count
        FROM incident
        GROUP BY system_key
        ORDER BY count DESC
        LIMIT 6
    """)).mappings().all()
    inc_rows = [{'system': _canonical_system_label(r['system_key']), 'count': r['count']} for r in inc_rows_raw]

    # KPIs
    total_incidents = Incident.query.count()

    incomplete_q = Incident.query.filter(
        db.or_(Incident.governance_comments.is_(None),
               db.func.trim(Incident.governance_comments) == '')
    )
    open_incidents = incomplete_q.count()

    awaiting_im = Incident.query.filter(
        db.func.upper(db.func.coalesce(Incident.reviewer, '')) == 'IM',
        db.or_(
            Incident.im_comments.is_(None), db.func.trim(Incident.im_comments) == '',
            Incident.im_signature.is_(None), db.func.trim(Incident.im_signature) == ''
        )
    ).count()

    awaiting_sdm = Incident.query.filter(
        db.func.upper(db.func.coalesce(Incident.reviewer, '')) == 'SDM',
        db.or_(
            Incident.sdm_comments.is_(None), db.func.trim(Incident.sdm_comments) == '',
            Incident.sdm_signature.is_(None), db.func.trim(Incident.sdm_signature) == ''
        )
    ).count()

    # Recent incidents
    latest = Incident.query.order_by(Incident.created_at.desc()).limit(8).all()
    recent = [{
        'id': r.id,
        'number': r.number,
        'date': fmt_date(r.date),
        'system': r.channel_or_system or '—',
        'logger': r.incident_logger or '—',
        'complete': is_incident_complete(r)
    } for r in latest]

    # 14-day trend (based on the 'date' field)
    today = date.today()
    start = today - timedelta(days=13)
    buckets = { (start + timedelta(days=i)): 0 for i in range(14) }
    rows = db.session.execute(db.text("""
        SELECT date, COUNT(*) AS c
        FROM incident
        WHERE date >= :start AND date <= :end
        GROUP BY date
    """), {'start': start.isoformat(), 'end': today.isoformat()}).mappings().all()
    for row in rows:
        d = row['date']
        if isinstance(d, str):
            d = datetime.strptime(d, '%Y-%m-%d').date()
        if d in buckets:
            buckets[d] = row['c']
    series_labels = [(start + timedelta(days=i)).strftime('%b %d') for i in range(14)]
    series_values = [buckets[start + timedelta(days=i)] for i in range(14)]

    # (Optional) recent backups for admins
    backups = []
    if session.get('role') == 'admin':
        try:
            for name in sorted(os.listdir(BACKUP_DIR), reverse=True)[:5]:
                pth = os.path.join(BACKUP_DIR, name)
                if os.path.isfile(pth):
                    backups.append({
                        'name': name,
                        'mtime': datetime.fromtimestamp(os.path.getmtime(pth)).strftime('%Y-%m-%d %H:%M')
                    })
        except FileNotFoundError:
            pass

    return render_template(
        'index.html',
        title='Dashboard',
        inc_by_system=inc_rows,
        backups=backups,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        awaiting_im=awaiting_im,
        awaiting_sdm=awaiting_sdm,
        recent=recent,
        series_labels=series_labels,
        series_values=series_values
    )

# -------------------------
@app.route('/records')
@login_required
def records():
    # prevent auto-redirect for creators (admin/sd). Only IM/SDM would ever follow it.
    if session.get('role') not in ['im','sdm']:
        session.pop('post_save_redirect', None)

    redir = session.pop('post_save_redirect', None)
    if redir:
        return redirect(redir)

    q = (request.args.get('q') or '').strip().lower()
    name = (request.args.get('name') or '').strip().lower()
    d_from_raw = request.args.get('from')
    d_to_raw = request.args.get('to')
    sys_name = (request.args.get('sys') or '').strip().lower()

    def parse_date(s):
        try:
            return datetime.strptime(s, '%Y-%m-%d').date()
        except Exception:
            return None

    df = parse_date(d_from_raw) if d_from_raw else None
    dt = parse_date(d_to_raw) if d_to_raw else None

    inc_query = Incident.query
    if q:
        like = f"%{q}%"
        inc_query = inc_query.filter(
            db.or_(
                db.func.lower(Incident.number).like(like),
                db.func.lower(Incident.channel_or_system).like(like),
                db.func.lower(Incident.incident).like(like)
            )
        )
    if name:
        like = f"%{name}%"
        inc_query = inc_query.filter(
            db.or_(
                db.func.lower(Incident.incident_logger).like(like),
                db.func.lower(Incident.corrective_action_by).like(like),
                db.func.lower(Incident.reviewed_by).like(like),
            )
        )
    if sys_name:
        inc_query = inc_query.filter(db.func.lower(Incident.channel_or_system) == sys_name)
    if df: inc_query = inc_query.filter(Incident.date >= df)
    if dt: inc_query = inc_query.filter(Incident.date <= dt)
    inc_query = inc_query.order_by(Incident.created_at.desc())

    items = inc_query.all()
    current_name = current_full_name_or_username()
    role = (session.get('role') or '').lower()
    ids = [it.id for it in items]
    att_counts = {i: c for (i, c) in db.session.query(IncidentAttachment.incident_id, func.count(IncidentAttachment.id))
                    .filter(IncidentAttachment.incident_id.in_(ids) if ids else False)
                    .group_by(IncidentAttachment.incident_id).all()}
    incidents = []
    for i in items:
        reviewer = (i.reviewer or '').upper()
        reviewer_commented = (reviewer == 'IM' and (i.im_comments or '').strip()) or (reviewer == 'SDM' and (i.sdm_comments or '').strip())
        can_edit = (role in ['ne','sd']) and ((i.incident_logger or '').strip() == current_name) and (not reviewer_commented)
        incidents.append({
            'id': i.id, 'number': i.number, 'date': fmt_date(i.date),
            'system': i.channel_or_system, 'logger': i.incident_logger,
            'complete': is_incident_complete(i),
            'has_attachment': bool(att_counts.get(i.id)),
            'can_edit': bool(can_edit),
        })

    # NEW: summary chips for improved records page
    total_count = len(incidents)
    complete_count = sum(1 for r in incidents if r['complete'])
    open_count = total_count - complete_count

    # Build "Download All" URL with the same filters
    params = {
        'q': request.args.get('q', ''),
        'name': request.args.get('name', ''),
        'from': request.args.get('from', ''),
        'to': request.args.get('to', ''),
        'sys': request.args.get('sys', ''),
    }
    export_url = url_for('export_records_range') + '?' + urlencode(params)

    return render_template('records.html',
                           incidents=incidents,
                           export_count=len(incidents),
                           export_url=export_url,
                           total_count=total_count,
                           complete_count=complete_count,
                           open_count=open_count,
                           title='Records')

# -------------------------
# Export all incidents in current filter as ZIP (CSVs + PDFs)
# -------------------------
@app.get('/records/incidents/export-range', endpoint='export_records_range')
@login_required
def export_records_range():
    q = (request.args.get('q') or '').strip().lower()
    name = (request.args.get('name') or '').strip().lower()
    d_from_raw = request.args.get('from')
    d_to_raw = request.args.get('to')
    sys_name = (request.args.get('sys') or '').strip().lower()

    def parse_date(s):
        try: return datetime.strptime(s, '%Y-%m-%d').date()
        except Exception: return None

    df = parse_date(d_from_raw) if d_from_raw else None
    dt = parse_date(d_to_raw) if d_to_raw else None

    inc_query = Incident.query
    if q:
        like = f"%{q}%"
        inc_query = inc_query.filter(
            db.or_(
                db.func.lower(Incident.number).like(like),
                db.func.lower(Incident.channel_or_system).like(like),
                db.func.lower(Incident.incident).like(like)
            )
        )
    if name:
        like = f"%{name}%"
        inc_query = inc_query.filter(
            db.or_(
                db.func.lower(Incident.incident_logger).like(like),
                db.func.lower(Incident.corrective_action_by).like(like),
                db.func.lower(Incident.reviewed_by).like(like),
            )
        )
    if sys_name:
        inc_query = inc_query.filter(db.func.lower(Incident.channel_or_system) == sys_name)
    if df: inc_query = inc_query.filter(Incident.date >= df)
    if dt: inc_query = inc_query.filter(Incident.date <= dt)

    recs = inc_query.order_by(Incident.created_at.desc()).all()
    if not recs:
        flash('No records found for the selected filters.', 'warning')
        return redirect(url_for('records'))

    PDF_LIMIT = 300

    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        # CSV of the filtered incidents
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            'id','number','date','incident_logger','system','incident',
            'time_of_incident','time_of_resolution','date_of_resolution','root_cause','impact',
            'corrective_action','corrective_action_by',
            'im_comments','im_signature','sdm_comments','sdm_signature',
            'governance_comments','governance_signature'
        ])
        for r in recs:
            writer.writerow([
                r.id, r.number, fmt_date(r.date), r.incident_logger, r.channel_or_system, r.incident,
                r.time_of_incident, r.time_of_resolution, fmt_date(r.date_of_resolution), r.root_cause, r.impact,
                r.corrective_action, r.corrective_action_by,
                r.im_comments, r.im_signature, r.sdm_comments, r.sdm_signature,
                r.governance_comments, r.governance_signature
            ])
        
        z.writestr('incidents.csv', out.getvalue().encode('utf-8-sig'))

        # PDFs for each record (capped to keep ZIP size reasonable)
        for idx, rec in enumerate(recs):
            if idx >= PDF_LIMIT:
                break

            # Build the same rows as individual export
            rev_raw = (rec.reviewer or '').strip().upper()
            reviewer_display = rev_raw if rev_raw in ('IM','SDM') else '— not assigned —'
            pending = not is_incident_complete(rec)
            pending_banner = None
            if pending:
                if session.get('role') in ['sd','ne']:
                    pending_banner = "Pending: awaiting IM/SDM input"
                elif session.get('role') == 'im':
                    pending_banner = "Pending: awaiting IM review"
                elif session.get('role') == 'sdm':
                    pending_banner = "Pending: awaiting SDM review"
                elif session.get('role') == 'gm':
                    pending_banner = "Pending: GM comment"

            rows = [
                ("Number", rec.number),
                ("Date", fmt_date(rec.date)),
                ("System/Channel", rec.channel_or_system),
                ("Incident Narrative", rec.incident or ""),
                ("Root Cause", rec.root_cause or ""),
                ("Impact", rec.impact or ""),
                ("Corrective Action", rec.corrective_action or ""),
                ("Corrective Action By", rec.corrective_action_by or ""),
                ("Reviewer", reviewer_display),
                ("SDM Comment", rec.sdm_comments or ""),
                ("SDM Signature", rec.sdm_signature or ""),
                ("IM Comment", rec.im_comments or ""),
                ("IM Signature", rec.im_signature or ""),
                ("Governance Comments", rec.governance_comments or ""),
                ("Governance Signature", rec.governance_signature or ""),
            ]

            html = render_template(
                'pdf_exec.html',
                title=f"Incident Report — {rec.number}",
                rows=rows,
                kind='incident',
                rid=rec.id,
                now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                brand="Incident Logger"
            )
            pdf_io = BytesIO()
            pisa.CreatePDF(src=html, dest=pdf_io)
            pdf_io.seek(0)
            z.writestr(f"{rec.number}.pdf", pdf_io.read())

        # Add attachments for each record under attachments/<number>/
        for rec in recs:
            atts = IncidentAttachment.query.filter_by(incident_id=rec.id).all()
            for a in atts:
                pth = os.path.join(UPLOAD_DIR, a.stored_path)
                if os.path.exists(pth):
                    with open(pth, 'rb') as fh:
                        z.writestr(f"attachments/{rec.number}/{a.id}_{a.original_name}", fh.read())

        if len(recs) > PDF_LIMIT:
            z.writestr('README.txt',
                       f"PDFs capped at {PDF_LIMIT} to keep file size reasonable. "
                       f"All rows are present in incidents.csv.")
    buf.seek(0)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    range_part = f"{d_from_raw or 'all'}_{d_to_raw or 'all'}"
    fname = f"incidents_{range_part}_{stamp}.zip"
    log_audit('EXPORT', 'Incident', None,
              f"{current_username()} exported {len(recs)} incidents as {fname} (range {range_part})")
    return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=fname)

# -------------------------
# Alerts page (incl delete requests)
# -------------------------
@app.route('/alerts')
@login_required
@roles_required('gm','im','sdm')
def alerts():
    # Corrected: this route previously returned admin health JSON by mistake.
    role = session.get('role')
    items = []

    if role in ['im', 'sdm']:
        target = 'IM' if role == 'im' else 'SDM'
        q = Incident.query.filter(
            db.func.upper(db.func.coalesce(Incident.reviewer, '')) == target
        ).order_by(Incident.created_at.desc())
        for rec in q.all():
            if (role == 'im' and needs_im_on_incident(rec)) or (role == 'sdm' and needs_sdm_on_incident(rec)):
                items.append({
                    'kind': 'incident',
                    'number': rec.number,
                    'date': fmt_date(rec.date),
                    'system': rec.channel_or_system,
                    'action': f"Enter {target} comment & signature",
                    'link': url_for('incident_im', rid=rec.id) if role == 'im' else url_for('incident_sdm', rid=rec.id)
                })
        return render_template('alerts.html', items=items, title='Alerts')

    if role == 'gm':
        for rec in Incident.query.order_by(Incident.created_at.desc()).all():
            rev = (rec.reviewer or '').upper()
            reviewer_pending = (rev == 'IM' and needs_im_on_incident(rec)) or (rev == 'SDM' and needs_sdm_on_incident(rec))
            gm_pending = not is_incident_complete(rec)
            if reviewer_pending or gm_pending:
                can = not reviewer_pending  # GM can act only when reviewer is done
                items.append({
                    'kind': 'incident',
                    'number': rec.number,
                    'date': fmt_date(rec.date),
                    'system': rec.channel_or_system,
                    'action': 'Governance comments & signature' if can else f"Waiting for {(rec.reviewer or 'IM/SDM').upper()} review",
                    'link': url_for('incident_governance', rid=rec.id)
                })

        # Include pending delete requests for GM
        for dr in DeleteRequest.query.filter_by(status='pending').order_by(DeleteRequest.created_at.desc()).all():
            label = f"{dr.entity_type} #{dr.entity_id}"
            if dr.entity_type == 'Incident':
                rec = db.session.get(Incident, dr.entity_id)
                if rec:
                    label = f"Incident {rec.number}"
            elif dr.entity_type == 'User':
                u = db.session.get(User, dr.entity_id)
                if u:
                    label = f"User {u.username}"
            items.append({
                'kind': 'delete request',
                'number': label,
                'date': dr.created_at.strftime('%Y-%m-%d'),
                'system': '-',
                'action': f"Approve or reject — by {dr.requested_by}",
                'link': url_for('list_delete_requests')
            })

    return render_template('alerts.html', items=items, title='Alerts')


@app.get('/admin/health')
@login_required
@roles_required('admin')
def admin_health():
    """Admin health dashboard (HTML) and JSON when ?format=json."""
    # Recompute on demand or if stale
    try:
        if request.args.get('refresh'):
            _compute_health_metrics()
        else:
            stale_sec = HEALTH.get('interval_seconds', 60) * 2
            last = HEALTH.get('last_run')
            if not last or (datetime.now(timezone.utc) - last).total_seconds() > stale_sec:
                _compute_health_metrics()
    except Exception:
        pass

    if (request.args.get('format') or '').lower() == 'json':
        def dt_iso(dt):
            try: return dt.isoformat()
            except Exception: return None
        payload = {
            'status': 'ok' if HEALTH.get('metrics', {}).get('db_ok') else 'degraded',
            'started_at': dt_iso(HEALTH.get('started_at')),
            'last_run': dt_iso(HEALTH.get('last_run')),
            'interval_seconds': HEALTH.get('interval_seconds'),
            'metrics': HEALTH.get('metrics', {}),
        }
        return jsonify(payload)

    # HTML
    return render_template('admin_health.html', data=HEALTH, now=datetime.now(timezone.utc), title='Admin Health')

def _system_choices():
    rows = System.query.filter_by(active=True).order_by(System.name.asc()).all()
    return [(r.name, r.name) for r in rows]

# -------------------------
# Incident create + governance
# -------------------------
@app.route('/incidents/new', methods=['GET','POST'])
@login_required
@roles_required('admin','sd','ne')
def new_incident():
    form = IncidentForm()
    form.channel_or_system.choices = _system_choices()

    # Server-known logged-by (enforced & prefilled)
    u = db.session.get(User, session['user_id'])
    logged_by_name = (u.full_name or u.username).strip()

    # Prefill field on first load
    if request.method == 'GET' and not form.incident_logger.data:
        form.incident_logger.data = logged_by_name

    # Auto-select reviewer by role (SD→SDM, NE→IM)
    role = (session.get('role') or '').lower()
    if role == 'sd':
        form.reviewer.choices = [('SDM','Service Delivery Manager')]
        form.reviewer.data = 'SDM'
    elif role == 'ne':
        form.reviewer.choices = [('IM','Infrastructure Manager')]
        form.reviewer.data = 'IM'
    else:
        form.reviewer.choices = [('IM','Infrastructure Manager'), ('SDM','Service Delivery Manager')]


    if form.validate_on_submit():
        rec = Incident(
            number=next_number('INCIDENT'),
            date=form.date.data,
            incident_logger=logged_by_name,  # enforce server value, ignore client input
            channel_or_system=form.channel_or_system.data,
            incident=form.incident.data,
            time_of_incident=form.time_of_incident.data or '',
            time_of_resolution=form.time_of_resolution.data or '',
            date_of_resolution=form.date_of_resolution.data,
            root_cause=form.root_cause.data or '',
            impact=form.impact.data or '',
            corrective_action=form.corrective_action.data or '',
            corrective_action_by=form.corrective_action_by.data or '',
            reviewer=form.reviewer.data
        )
        db.session.add(rec)
        db.session.commit()
        log_audit('CREATE', 'Incident', rec.id, f"{current_username()} created {rec.number}")
        # Save any uploaded attachments
        _save_incident_attachments(rec, request.files.getlist('attachments'))

        try:
            session['post_save_redirect'] = url_for('incident_im', rid=rec.id) if (rec.reviewer or '').upper() == 'IM' \
                                            else url_for('incident_sdm', rid=rec.id)
        except Exception:
            pass

        flash('Incident logged.', 'success')
        return redirect(url_for('records'))
    return render_template('incident_new.html', form=form, title='New Incident')


# Allow NE/SD to edit *their own* incident until reviewer has commented
@app.route('/incidents/<int:rid>/edit', methods=['GET','POST'])
@login_required
@roles_required('ne','sd')

def edit_incident(rid):
    rec = Incident.query.get_or_404(rid)
    attachments = IncidentAttachment.query.filter_by(incident_id=rec.id).order_by(IncidentAttachment.id.asc()).all()

    # Only the original logger may edit
    if (rec.incident_logger or '').strip() != current_full_name_or_username():
        abort(403)

    # Lock once reviewer has commented
    if reviewer_has_commented(rec):
        flash('Locked: the assigned reviewer has already added their comment.', 'warning')
        return redirect(url_for('record_view', kind='incident', rid=rec.id))

    form = IncidentForm(obj=rec)
    form.channel_or_system.choices = _system_choices() or [(rec.channel_or_system, rec.channel_or_system)]

    # Keep server-trusted fields
    form.incident_logger.data = rec.incident_logger

    # Ensure reviewer field shows the existing choice but cannot be changed (enforced server-side)
    role = (session.get('role') or '').lower()
    if role == 'sd':
        form.reviewer.choices = [('SDM','Service Delivery Manager')]
        form.reviewer.data = 'SDM'
    elif role == 'ne':
        form.reviewer.choices = [('IM','Infrastructure Manager')]
        form.reviewer.data = 'IM'
    else:
        form.reviewer.choices = [(rec.reviewer or '', rec.reviewer or '')]
        form.reviewer.data = rec.reviewer

    if request.method == 'POST' and form.validate():
        # Re-check lock just before saving in case state changed
        if reviewer_has_commented(rec):
            flash('Locked: the assigned reviewer has already added their comment.', 'warning')
            return redirect(url_for('record_view', kind='incident', rid=rec.id))

        # Update editable fields
        rec.date = form.date.data
        rec.channel_or_system = form.channel_or_system.data
        rec.incident = form.incident.data
        rec.time_of_incident = form.time_of_incident.data or ''
        rec.time_of_resolution = form.time_of_resolution.data or ''
        rec.root_cause = form.root_cause.data or ''
        rec.impact = form.impact.data or ''
        rec.corrective_action = form.corrective_action.data or ''
        rec.corrective_action_by = form.corrective_action_by.data or ''
        # Do not change rec.reviewer

        # Delete any selected attachments
        del_ids = [int(x) for x in request.form.getlist('delete_attachment_ids') if str(x).isdigit()]
        removed = []
        for aid in del_ids:
            att = IncidentAttachment.query.filter_by(id=aid, incident_id=rec.id).first()
            if att:
                try:
                    path = os.path.join(UPLOAD_DIR, att.stored_path)
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
                removed.append(att.original_name or f"attachment {aid}")
                db.session.delete(att)

        # Save any newly uploaded attachments
        _save_incident_attachments(rec, request.files.getlist('attachments'))

        db.session.commit()

        if removed:
            log_audit('DELETE', 'Incident', rec.id, f"{current_username()} removed attachments: " + ', '.join(removed))
        log_audit('UPDATE', 'Incident', rec.id, f"{current_username()} edited {rec.number}")
        flash('Incident updated.', 'success')
        return redirect(url_for('record_view', kind='incident', rid=rec.id))

    return render_template('incident_edit.html', form=form, rec=rec, attachments=attachments, title='Edit Incident')

@app.route('/incidents/<int:rid>/governance', methods=['GET','POST'])
@login_required
@roles_required('gm')
def incident_governance(rid):
    rec = Incident.query.get_or_404(rid)
    attachments = IncidentAttachment.query.filter_by(incident_id=rec.id).order_by(IncidentAttachment.id.asc()).all()
    form = IncidentGovForm(obj=rec)
    gm_ready = gm_can_comment(rec)

    if request.method == 'GET':
        if not gm_ready:
            flash(f"Awaiting {(rec.reviewer or 'IM/SDM')} review before GM can comment.", 'info')
        if not rec.governance_signature:
            form.governance_signature.data = current_full_name_or_username()

    if form.validate_on_submit():
        if not gm_ready:
            flash(f"Awaiting {(rec.reviewer or 'IM/SDM')} review before GM can comment.", 'info')
        else:
            rec.governance_comments = form.governance_comments.data
            rec.governance_signature = current_full_name_or_username()  # enforce server-side
            db.session.commit()
            log_audit('UPDATE', 'Incident', rec.id, f"{current_username()} updated governance for {rec.number}")
            flash('Governance updated.', 'success')
            return redirect(url_for('records'))
    return render_template('incident_gov.html', form=form, rec=rec, gm_ready=gm_ready, attachments=attachments, title='Incident Governance')

# IM and SDM dedicated review routes with auto-signatures
@app.route('/incidents/<int:rid>/im', methods=['GET','POST'])
@login_required
@roles_required('im','admin','sd')
def incident_im(rid):
    rec = Incident.query.get_or_404(rid)
    attachments = IncidentAttachment.query.filter_by(incident_id=rec.id).order_by(IncidentAttachment.id.asc()).all()
    form = IMReviewForm()
    if request.method == 'GET':
        form.im_comments.data = rec.im_comments or ''
        form.im_signature.data = rec.im_signature or current_full_name_or_username()
    if form.validate_on_submit():
        rec.im_comments = form.im_comments.data
        rec.im_signature = current_full_name_or_username()  # enforce server-side
        db.session.commit()
        log_audit('UPDATE', 'Incident', rec.id, f"{current_username()} IM review saved for {rec.number}")
        flash('Infrastructure Manager review saved.', 'success')
        return redirect(url_for('records'))
    return render_template('incident_im.html', form=form, rec=rec, attachments=attachments, title='IM Review')

@app.route('/incidents/<int:rid>/sdm', methods=['GET','POST'])
@login_required
@roles_required('sdm','admin','sd')
def incident_sdm(rid):
    rec = Incident.query.get_or_404(rid)
    attachments = IncidentAttachment.query.filter_by(incident_id=rec.id).order_by(IncidentAttachment.id.asc()).all()
    form = SDMReviewForm()
    if request.method == 'GET':
        form.sdm_comments.data = rec.sdm_comments or ''
        form.sdm_signature.data = rec.sdm_signature or current_full_name_or_username()
    if form.validate_on_submit():
        rec.sdm_comments = form.sdm_comments.data
        rec.sdm_signature = current_full_name_or_username()  # enforce server-side
        db.session.commit()
        log_audit('UPDATE', 'Incident', rec.id, f"{current_username()} SDM review saved for {rec.number}")
        flash('Service Delivery Manager review saved.', 'success')
        return redirect(url_for('records'))
    return render_template('incident_sdm.html', form=form, rec=rec, attachments=attachments, title='SDM Review')


# -------------------------
# Admin Settings — Systems
# -------------------------

@app.route('/admin/password-policy', methods=['GET','POST'])
@login_required
@privs_required('can_manage_password_policy')
def password_policy():
    pol = _get_policy()
    if request.method == 'POST':
        try:
            pol.min_length = int(request.form.get('min_length') or pol.min_length or 12)
            pol.expiry_days = int(request.form.get('expiry_days') or pol.expiry_days or 0)
            pol.lockout_threshold = int(request.form.get('lockout_threshold') or pol.lockout_threshold or 3)
            pol.idle_timeout_minutes = int(request.form.get('idle_timeout_minutes') or pol.idle_timeout_minutes or 6)
            pol.require_upper = bool(request.form.get('require_upper'))
            pol.require_lower = bool(request.form.get('require_lower'))
            pol.require_number = bool(request.form.get('require_number'))
            pol.require_special = bool(request.form.get('require_special'))
            db.session.commit()
            # Apply idle timeout live
            app.permanent_session_lifetime = timedelta(minutes=pol.idle_timeout_minutes or 6)
            log_audit('UPDATE', 'PasswordPolicy', pol.id, f"{current_username()} updated password policy (via tab)")
            flash('Password policy updated.', 'success')
            return redirect(url_for('password_policy'))
        except Exception as _e:
            flash('Failed to update password policy.', 'danger')
    return render_template('password_policy.html', pol=pol, title='Password Policy')

@app.route('/admin/settings', methods=['GET','POST'])
@login_required
@roles_required('admin')
def admin_settings():
    if request.method == 'POST':
        section = (request.form.get('section') or 'systems').strip()
        if section == 'systems':
            name = (request.form.get('name') or '').strip()
            if name:
                if System.query.filter(func.lower(System.name) == name.lower()).first():
                    flash('System already exists.', 'info')
                else:
                    s = System(name=name.strip(), active=True)
                    db.session.add(s); db.session.commit()
                    log_audit('CREATE', 'System', s.id, f"{current_username()} added system '{s.name}'")
                    flash('System added.', 'success')
        elif section == 'policy':
            pol = _get_policy()
            try:
                pol.min_length = int(request.form.get('min_length') or pol.min_length or 12)
                pol.expiry_days = int(request.form.get('expiry_days') or pol.expiry_days or 90)
                pol.lockout_threshold = int(request.form.get('lockout_threshold') or pol.lockout_threshold or 3)
                pol.idle_timeout_minutes = int(request.form.get('idle_timeout_minutes') or pol.idle_timeout_minutes or 6)
                pol.require_upper = bool(request.form.get('require_upper'))
                pol.require_lower = bool(request.form.get('require_lower'))
                pol.require_number = bool(request.form.get('require_number'))
                pol.require_special = bool(request.form.get('require_special'))
                db.session.commit()
                # apply idle timeout live
                app.permanent_session_lifetime = timedelta(minutes=pol.idle_timeout_minutes or 6)
                log_audit('UPDATE', 'PasswordPolicy', pol.id, f"{current_username()} updated password policy")
                flash('Password policy updated.', 'success')
            except Exception as e:
                flash('Failed to update password policy.', 'danger')
        return redirect(url_for('admin_settings'))
    systems = System.query.order_by(System.name.asc()).all()
    pol = _get_policy()
    return render_template('settings.html', systems=systems, pol=pol, title='Settings')

@app.post('/admin/settings/systems/<int:sid>/toggle')
@login_required
@roles_required('admin')
def toggle_system(sid):
    s = System.query.get_or_404(sid)
    s.active = not s.active
    db.session.commit()
    log_audit('UPDATE', 'System', s.id, f"{current_username()} {'enabled' if s.active else 'disabled'} system '{s.name}'")
    return redirect(url_for('admin_settings'))

@app.post('/admin/settings/systems/<int:sid>/delete')
@login_required
@roles_required('admin')
def delete_system(sid):
    s = System.query.get_or_404(sid)
    db.session.delete(s); db.session.commit()
    log_audit('DELETE', 'System', s.id, f"{current_username()} deleted system '{s.name}'")
    flash('System removed.', 'success')
    return redirect(url_for('admin_settings'))

# -------------------------
# Two-person delete workflow (GM approval)
# -------------------------
def _entity_label(entity_type, entity_id):
    if entity_type == 'Incident':
        rec = db.session.get(Incident, entity_id)
        return f"Incident {rec.number}" if rec else f"Incident #{entity_id}"
    if entity_type == 'User':
        u = db.session.get(User, entity_id)
        return f"User {u.username}" if u else f"User #{entity_id}"
    return f"{entity_type} #{entity_id}"

# Admin raises a delete request for an Incident
@app.route('/records/<kind>/<int:rid>/request-delete', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def request_delete_record(kind, rid):
    if kind != 'incident':
        abort(404)
    rec = Incident.query.get_or_404(rid)

    pending = DeleteRequest.query.filter_by(entity_type='Incident', entity_id=rid, status='pending').first()
    if pending:
        flash('A delete request for this record is already pending GM approval.', 'info')
        return redirect(url_for('records'))

    if request.method == 'POST':
        reason = (request.form.get('reason') or '').strip()
        if not reason:
            flash('Reason is required.', 'danger')
            return render_template('delete_request_form.html',
                                   entity_label=_entity_label('Incident', rid),
                                   back_url=url_for('records'), title='Request Delete')
        dr = DeleteRequest(
            entity_type='Incident', entity_id=rid, reason=reason,
            requested_by=current_username(), status='pending'
        )
        db.session.add(dr); db.session.commit()
        log_audit('DELETE_REQUEST', 'Incident', rid, f"{current_username()} requested delete: {rec.number} (reason: {reason[:120]})")
        flash('Delete request submitted for GM approval.', 'success')
        return redirect(url_for('records'))

    return render_template('delete_request_form.html',
                           entity_label=_entity_label('Incident', rid),
                           back_url=url_for('records'), title='Request Delete')

# Admin raises a delete request for a User
@app.route('/users/<int:user_id>/request-delete', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def request_delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == current_username():
        flash("You can't request to delete your own account.", 'warning')
        return redirect(url_for('view_users'))
    if u.role == 'admin' and User.query.filter_by(role='admin', is_disabled=False).count() <= 1:
        flash("You can't delete the last active admin.", 'warning')
        return redirect(url_for('view_users'))

    pending = DeleteRequest.query.filter_by(entity_type='User', entity_id=user_id, status='pending').first()
    if pending:
        flash('A delete request for this user is already pending GM approval.', 'info')
        return redirect(url_for('view_users'))

    if request.method == 'POST':
        reason = (request.form.get('reason') or '').strip()
        if not reason:
            flash('Reason is required.', 'danger')
            return render_template('delete_request_form.html',
                                   entity_label=_entity_label('User', user_id),
                                   back_url=url_for('view_users'), title='Request Delete')
        dr = DeleteRequest(
            entity_type='User', entity_id=user_id, reason=reason,
            requested_by=current_username(), status='pending'
        )
        db.session.add(dr); db.session.commit()
        log_audit('DELETE_REQUEST', 'User', user_id, f"{current_username()} requested delete: {u.username} (reason: {reason[:120]})")
        flash('Delete request submitted for GM approval.', 'success')
        return redirect(url_for('view_users'))

    return render_template('delete_request_form.html',
                           entity_label=_entity_label('User', user_id),
                           back_url=url_for('view_users'), title='Request Delete')

# GM list/approve/reject
@app.get('/admin/delete-requests')
@privs_required('can_approve_delete')
@login_required
@roles_required('gm')
def list_delete_requests():
    rows = []
    for r in DeleteRequest.query.filter_by(status='pending').order_by(DeleteRequest.created_at.desc()).all():
        rows.append({
            'id': r.id,
            'created_at': r.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'requested_by': r.requested_by,
            'entity_label': _entity_label(r.entity_type, r.entity_id),
            'reason': r.reason
        })
    return render_template('delete_requests_list.html', rows=rows, title='Delete Requests')

@app.post('/admin/delete-requests/<int:drid>/approve')
@login_required
@roles_required('gm')
def approve_delete_request(drid):
    r = DeleteRequest.query.get_or_404(drid)
    if r.status != 'pending':
        flash('Request is not pending.', 'warning')
        return redirect(url_for('list_delete_requests'))

    r.status = 'approved'
    r.approved_by = current_username()
    r.approved_at = datetime.now(timezone.utc)

    # Perform the actual deletion
    if r.entity_type == 'Incident':
        obj = db.session.get(Incident, r.entity_id)
        if obj:
            label = obj.number
            _cleanup_incident_attachments(obj.id)
            db.session.delete(obj)
            log_audit('DELETE', 'Incident', r.entity_id, f"{current_username()} (GM) approved and deleted {label}")
    elif r.entity_type == 'User':
        obj = db.session.get(User, r.entity_id)
        if obj:
            username = obj.username
            db.session.delete(obj)
            log_audit('DELETE', 'User', r.entity_id, f"{current_username()} (GM) approved and deleted user {username}")
    db.session.commit()

    log_audit('DELETE_APPROVED', r.entity_type, r.entity_id, f"{current_username()} approved delete request #{r.id}")
    flash('Delete approved and record removed.', 'success')
    return redirect(url_for('list_delete_requests'))

@app.post('/admin/delete-requests/<int:drid>/reject')
@login_required
@roles_required('gm')
def reject_delete_request(drid):
    r = DeleteRequest.query.get_or_404(drid)
    if r.status != 'pending':
        flash('Request is not pending.', 'warning')
        return redirect(url_for('list_delete_requests'))
    r.status = 'rejected'
    r.approved_by = current_username()
    r.approved_at = datetime.now(timezone.utc)
    db.session.commit()
    log_audit('DELETE_REJECTED', r.entity_type, r.entity_id, f"{current_username()} rejected delete request #{r.id}")
    flash('Delete request rejected.', 'info')
    return redirect(url_for('list_delete_requests'))

def _cleanup_incident_attachments(incident_id: int):
    """Delete attachment files from disk and remove rows for a given incident_id."""
    try:
        atts = IncidentAttachment.query.filter_by(incident_id=incident_id).all()
        for a in atts:
            try:
                if a.stored_path:
                    p = os.path.join(UPLOAD_DIR, a.stored_path)
                    if os.path.isfile(p):
                        os.remove(p)
            except Exception as _del_ex:
                # Log but continue
                print("[cleanup] failed to remove", a.stored_path, _del_ex)
            db.session.delete(a)
        db.session.commit()
    except Exception as _ex:
        print("[cleanup] error during incident attachment cleanup:", _ex)

# -------------------------
# Delete routes (deprecated: disabled to enforce approval flow)
# -------------------------
@app.route('/records/<kind>/<int:rid>/delete', methods=['POST'])
@login_required
def delete_record(kind, rid):
    flash('Direct delete is disabled. Use "Request Delete" (GM approval required).', 'warning')
    return redirect(url_for('records'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    flash('Direct delete is disabled. Use "Request Delete" (GM approval required).', 'warning')
    return redirect(url_for('view_users'))

# -------------------------
# Users (view/create/reset/toggle/edit)
# -------------------------


# -------------------------
# Admin: Roles & Privileges
# -------------------------
@app.get('/admin/roles')
@login_required
@privs_required('can_manage_roles')
def view_roles():
    roles = Role.query.order_by(Role.name).all()
    privs = Privilege.query.order_by(Privilege.code).all()
    return render_template_string(r"""
    {% extends "base.html" %}
    {% block body %}
    <h2 class="mb-3">Roles &amp; Privileges</h2>
    <a class="btn btn-primary mb-3" href="{{ url_for('new_role') }}">New Role</a>
    <table class="table table-bordered table-sm align-middle">
      <thead><tr><th>Role</th><th>Description</th><th>Privileges</th><th style="width:160px">Actions</th></tr></thead>
      <tbody>
      {% for r in roles %}
        <tr>
          <td><strong>{{ r.name }}</strong></td>
          <td>{{ r.description }}</td>
          <td>
            {% for p in r.privileges %}
              <span class="badge text-bg-secondary mb-1">{{ p.code }}</span>
            {% else %}
              <em>None</em>
            {% endfor %}
          </td>
          <td>
            <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('edit_role', rid=r.id) }}">Edit</a>
            <form method="post" action="{{ url_for('delete_role', rid=r.id) }}" style="display:inline" onsubmit="return confirm('Delete role {{r.name}}?');">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <button class="btn btn-sm btn-outline-danger">Delete</button>
            </form>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% endblock %}
    """, roles=roles, privs=privs)

@app.get('/admin/roles/new')
@login_required
@privs_required('can_manage_roles')
def new_role():
    privs = Privilege.query.order_by(Privilege.code).all()
    return render_template_string(r"""
    {% extends "base.html" %}
    {% block body %}
    <h2>Create Role</h2>
    <form method="post" action="{{ url_for('new_role') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="mb-3">
        <label class="form-label">Role Name</label>
        <input class="form-control" name="name" required maxlength="64">
      </div>
      <div class="mb-3">
        <label class="form-label">Description</label>
        <input class="form-control" name="description" maxlength="255">
      </div>
      <div class="mb-3">
        <label class="form-label">Privileges</label><br>
        {% for p in privs %}
          <label class="form-check form-check-inline">
            <input class="form-check-input" type="checkbox" name="priv" value="{{p.code}}">
            <span class="form-check-label">{{ p.code }}</span>
          </label>
        {% endfor %}
      </div>
      <button class="btn btn-primary">Create</button>
      <a class="btn btn-link" href="{{ url_for('view_roles') }}">Cancel</a>
    </form>
    {% endblock %}
    """, privs=privs)

@app.post('/admin/roles/new')
@login_required
@privs_required('can_manage_roles')
def new_role_post():
    name = (request.form.get('name') or '').strip().lower()
    desc = (request.form.get('description') or '').strip()
    if not name:
        flash('Provide a role name.', 'warning')
        return redirect(url_for('new_role'))
    # Prevent clobbering default roles accidentally
    existing = Role.query.filter_by(name=name).first()
    if existing:
        flash('Role already exists.', 'warning')
        return redirect(url_for('view_roles'))
    r = Role(name=name, description=desc)
    codes = request.form.getlist('priv')
    r.privileges = Privilege.query.filter(Privilege.code.in_(codes)).all() if codes else []
    db.session.add(r); db.session.commit()
    flash('Role created.', 'success')
    return redirect(url_for('view_roles'))

@app.get('/admin/roles/<int:rid>/edit')
@login_required
@privs_required('can_manage_roles')
def edit_role(rid):
    r = Role.query.get_or_404(rid)
    privs = Privilege.query.order_by(Privilege.code).all()
    selected = {p.code for p in r.privileges}
    return render_template_string(r"""
    {% extends "base.html" %}
    {% block body %}
    <h2>Edit Role: {{ r.name }}</h2>
    <form method="post" action="{{ url_for('edit_role', rid=r.id) }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="mb-3">
        <label class="form-label">Description</label>
        <input class="form-control" name="description" maxlength="255" value="{{ r.description }}">
      </div>
      <div class="mb-3">
        <label class="form-label">Privileges</label><br>
        {% for p in privs %}
          <label class="form-check form-check-inline">
            <input class="form-check-input" type="checkbox" name="priv" value="{{p.code}}" {% if p.code in selected %}checked{% endif %}>
            <span class="form-check-label">{{ p.code }}</span>
          </label>
        {% endfor %}
      </div>
      <button class="btn btn-primary">Save</button>
      <a class="btn btn-link" href="{{ url_for('view_roles') }}">Cancel</a>
    </form>
    {% endblock %}
    """, r=r, privs=privs, selected=selected)

@app.post('/admin/roles/<int:rid>/edit')
@login_required
@privs_required('can_manage_roles')
def edit_role_post(rid):
    r = Role.query.get_or_404(rid)
    r.description = (request.form.get('description') or '').strip()
    codes = request.form.getlist('priv')
    r.privileges = Privilege.query.filter(Privilege.code.in_(codes)).all() if codes else []
    db.session.commit()
    flash('Role updated.', 'success')
    return redirect(url_for('view_roles'))

@app.post('/admin/roles/<int:rid>/delete')
@login_required
@privs_required('can_manage_roles')
def delete_role(rid):
    r = Role.query.get_or_404(rid)
    if r.users:
        flash('Cannot delete a role that is assigned to users.', 'warning')
        return redirect(url_for('view_roles'))
    db.session.delete(r); db.session.commit()
    flash('Role deleted.', 'success')
    return redirect(url_for('view_roles'))

# Assign roles to a user
@app.get('/users/<int:uid>/roles')
@login_required
@privs_required('can_manage_roles')
def user_roles(uid):
    u = User.query.get_or_404(uid)
    roles = Role.query.order_by(Role.name).all()
    assigned = {r.id for r in getattr(u, 'roles', [])}
    return render_template_string(r"""
    {% extends "base.html" %}
    {% block body %}
    <h2>Assign Roles: {{ user.username }}</h2>
    <form method="post" action="{{ url_for('user_roles', uid=user.id, user=u, roles=roles, assigned=assigned, title='Assign Roles') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="mb-3">
        {% for r in roles %}
          <label class="form-check">
            <input class="form-check-input" type="checkbox" name="role_id" value="{{r.id}}" {% if r.id in assigned %}checked{% endif %}>
            <span class="form-check-label"><strong>{{ r.name }}</strong> — {{ r.description }}</span>
          </label>
        {% endfor %}
      </div>
      <button class="btn btn-primary">Save</button>
      <a class="btn btn-link" href="{{ url_for('view_users') }}">Back</a>
    </form>
    {% endblock %}
    """, user=u, roles=roles, assigned=assigned)

@app.post('/users/<int:uid>/roles')
@login_required
@privs_required('can_manage_roles')
def user_roles_post(uid):
    u = User.query.get_or_404(uid)
    ids = [int(x) for x in request.form.getlist('role_id')]
    u.roles = Role.query.filter(Role.id.in_(ids)).all() if ids else []
    db.session.commit()
    flash('User roles updated.', 'success')
    return redirect(url_for('user_roles', uid=uid))

@app.route('/users')
@login_required
def view_users():
    
    if session.get('role') not in ['admin', 'sd', 'view']:
        abort(403)
    users = User.query.order_by(User.username.asc()).all()

    # Compute last login per username (max AuditLog timestamp for LOGIN)
    rows = (db.session.query(AuditLog.username, db.func.max(AuditLog.timestamp))
            .filter(AuditLog.action == 'LOGIN')
            .group_by(AuditLog.username)
            .all())
    last_login_map = {u: ts for (u, ts) in rows}

    return render_template('users.html', users=users, last_login=last_login_map, title='Users')


@app.route('/users/new', methods=['GET','POST'])
@login_required
@roles_required('admin','sd','ne')
def new_user():
    form = NewUserForm()
    form.password.validators = [DataRequired()] + _build_password_validators()
    # Populate role choices dynamically from Role table (only active roles)
    roles = Role.query.filter_by(is_active=True).order_by(Role.name.asc()).all()
    form.role.choices = [(r.name, r.name.title()) for r in roles]

    if form.validate_on_submit():
        # Ensure selected role exists
        selected_role = next((r for r in roles if r.name == form.role.data), None)
        if not selected_role:
            flash('Selected role is not available.', 'danger')
            return render_template('new_user.html', form=form, title='Create User')
        if User.query.filter_by(username=form.username.data.strip()).first():
            flash('Username already exists.', 'danger')
            return render_template('new_user.html', form=form, title='Create User')
        u = User(
            title=form.title.data or '',
            first_name=form.first_name.data, last_name=form.last_name.data,
            username=form.username.data.strip(), role=form.role.data.strip()
        )
        u.set_password(form.password.data)
        u.password_changed_at = datetime.now(timezone.utc)
        u.force_password_change = True
        db.session.add(u); db.session.commit()
        log_audit('CREATE', 'User', u.id, f"{current_username()} created user {u.username}")
        flash('User created.', 'success')
        return redirect(url_for('view_users'))
    return render_template('new_user.html', form=form, title='Create User')

@app.route('/users/reset-password', methods=['GET','POST'])
@login_required
@roles_required('admin','sd','ne')
def reset_password():
    form = ResetUserForm()
    form.new_password.validators = [DataRequired()] + _build_password_validators()
    if request.method == 'POST':
        if form.validate():
            u = User.query.filter_by(username=form.username.data.strip()).first()
            if not u:
                flash('User not found.', 'danger')
            else:
                u.set_password(form.new_password.data)
                u.password_changed_at = datetime.now(timezone.utc)
                u.is_disabled = False
                u.failed_attempts = 0
                u.force_password_change = True
                db.session.commit()
                log_audit('UPDATE', 'User', u.id, f"{current_username()} reset password for {u.username}")
                flash('Password reset & user unlocked.', 'success')
                return redirect(url_for('view_users'))
        else:
            if form.new_password.errors:
                flash('Password does not meet password requirements (min 12 chars, 1 uppercase, 1 lowercase, 1 special character).', 'info')
    return render_template('reset_pw.html', form=form, title='Reset Password')

@app.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@roles_required('admin','sd','ne')
def toggle_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_disabled = not u.is_disabled
    if not u.is_disabled:
        u.failed_attempts = 0
    db.session.commit()
    action_str = 'disabled' if u.is_disabled else 'enabled'
    log_audit('UPDATE', 'User', u.id, f"{current_username()} {action_str} user {u.username}")
    flash('User status updated.', 'success')
    return redirect(url_for('view_users'))

@app.route('/users/<int:user_id>/edit', methods=['GET','POST'])
@login_required
@roles_required('admin','sd','ne')
def edit_user(user_id):
    u = User.query.get_or_404(user_id)
    form = EditUserForm(obj=u)
    if form.validate_on_submit():
        new_un = form.username.data.strip()
        if new_un != u.username and User.query.filter_by(username=new_un).first():
            flash('Username already exists.', 'danger')
        else:
            u.title = form.title.data or ''
            u.first_name = form.first_name.data
            u.last_name = form.last_name.data
            u.username = new_un
            db.session.commit()
            log_audit('UPDATE', 'User', u.id, f"{current_username()} edited profile for {u.username}")
            flash('User profile updated.', 'success')
            return redirect(url_for('view_users'))
    return render_template('user_edit.html', form=form, u=u, title='Edit User')

# -------------------------
# Audit Log (Admin + View)
# -------------------------
@app.route('/audit')
@login_required
def audit():
    if session.get('role') not in ['admin', 'sd', 'view']:
        abort(403)
    q = (request.args.get('q') or '').strip().lower()
    d_from = request.args.get('from')
    d_to = request.args.get('to')

    query = AuditLog.query
    if q:
        like = f"%{q}%"
        query = query.filter(db.or_(
            db.func.lower(AuditLog.username).like(like),
            db.func.lower(AuditLog.action).like(like),
            db.func.lower(AuditLog.entity_type).like(like),
            db.func.lower(AuditLog.details).like(like)
        ))

    def parse_date(s):
        try: return datetime.strptime(s, '%Y-%m-%d')
        except: return None

    if d_from:
        dt = parse_date(d_from)
        if dt: query = query.filter(AuditLog.timestamp >= dt.replace(tzinfo=timezone.utc))
    if d_to:
        dt = parse_date(d_to)
        if dt: query = query.filter(AuditLog.timestamp <= (dt + timedelta(days=1)).replace(tzinfo=timezone.utc))

    rows = query.order_by(AuditLog.timestamp.desc()).limit(1000).all()
    return render_template('audit.html', rows=rows, title='Audit')

# -------------------------
# Backups (Admin/SD)
# -------------------------
def export_csv(model_cls, columns):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns)
    for row in model_cls.query.all():
        vals = []
        for c in columns:
            v = getattr(row, c, '')
            if isinstance(v, (datetime, date)): v = fmt_date(v)
            vals.append(v)
        writer.writerow(vals)
    return out.getvalue().encode('utf-8-sig')

@app.get('/backup', endpoint='backup')
@login_required
@roles_required('admin','sd','ne')
@privs_required('can_backup')
def backup():
    # list .zip files in BACKUP_DIR
    files = []
    try:
        if os.path.isdir(BACKUP_DIR):
            files = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith('.zip')], reverse=True)
    except Exception:
        files = []
    return render_template('backup.html', files=files, title='Backup')

@app.post('/admin/backup', endpoint='create_backup')
@login_required
@roles_required('admin','sd','ne')
@privs_required('can_backup')
def create_backup():
    now = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    fname = f"incident_logger_backup_{now}.zip"
    path = os.path.join(BACKUP_DIR, fname)
    db_path = os.path.abspath(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', ''))
    meta = {
        'created_at_utc': now,
        'created_by': current_username(),
        'app': 'incident_logger',
        'version': '1.0'
    }

    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        if os.path.exists(db_path):
            z.write(db_path, arcname='incident_logger.db')
        z.writestr('incidents.csv', export_csv(Incident, [
            'id','number','date','incident_logger','channel_or_system','incident',
            'time_of_incident','time_of_resolution','date_of_resolution','root_cause','impact','corrective_action',
            'corrective_action_by','reviewed_by','reviewer_signature','governance_comments','governance_signature',
            'reviewer',
            'im_comments','im_signature','sdm_comments','sdm_signature'
        ]))
        z.writestr('unauthorized_changes.csv', export_csv(UnauthorizedChange, [
            'id','number','date','system','incident','time_occurred','root_cause','impact',
            'correction_taken','completed_by','completed_by_title','completed_by_signature',
            'section_manager','section_manager_signature','governance_manager','governance_manager_signature',
            'hod','hod_signature'
        ]))
        # Include all uploaded files (attachments)
        try:
            if os.path.isdir(UPLOAD_DIR):
                for root, dirs, files in os.walk(UPLOAD_DIR):
                    for name in files:
                        fpath = os.path.join(root, name)
                        rel = os.path.relpath(fpath, UPLOAD_DIR)
                        arc = os.path.join('uploads', rel)
                        try:
                            z.write(fpath, arcname=arc)
                        except Exception:
                            pass
        except Exception:
            pass
        z.writestr('meta.json', json.dumps(meta, indent=2))
    log_audit('EXPORT', 'System', None, f"{current_username()} created backup {fname}")
    flash('Backup created.', 'success')
    return redirect(url_for('index'))

@app.get('/admin/backups/<path:filename>')
@login_required
@roles_required('admin','sd','ne')
def download_backup(filename):
    return send_from_directory(BACKUP_DIR, filename, as_attachment=True)

# -------------------------
# PDF Export (Executive style)
# -------------------------
@app.get('/records/<kind>/<int:rid>/pdf', endpoint='record_pdf')
@login_required
def export_record_pdf(kind, rid):
    if kind == 'incident':
        rec = Incident.query.get_or_404(rid)
        title = f"Incident Report — {rec.number}"

        rev_raw = (rec.reviewer or '').strip().upper()
        reviewer_display = rev_raw if rev_raw in ('IM','SDM') else '— not assigned —'

        rows = [
            ("Number", rec.number),
            ("Date", fmt_date(rec.date)),
            ("System/Channel", rec.channel_or_system),
            ("Incident Narrative", rec.incident),
            ("Time of Incident", rec.time_of_incident or ""),
            ("Time of Resolution", rec.time_of_resolution or ""),
            ("Date of Resolution", fmt_date(rec.date_of_resolution)),
            ("Root Cause", rec.root_cause or ""),
            ("Impact", rec.impact or ""),
            ("Corrective Action", rec.corrective_action or ""),
            ("Corrective Action By", rec.corrective_action_by or ""),
            ("Reviewer", reviewer_display),
        ]

        if rev_raw == 'IM':
            rows += [
                ("IM Comment", rec.im_comments or "Pending — awaiting IM input"),
                ("IM Signature", rec.im_signature or "Pending"),
            ]
        elif rev_raw == 'SDM':
            rows += [
                ("SDM Comment", rec.sdm_comments or "Pending — awaiting SDM input"),
                ("SDM Signature", rec.sdm_signature or "Pending"),
            ]

        rows += [
            ("Governance Comments", rec.governance_comments or ""),
            ("Governance Signature", rec.governance_signature or ""),
        ]
        number   = rec.number
    else:
        abort(404)

    html = render_template(
        'pdf_exec.html',
        title=title, rows=rows, kind=kind, rid=rid,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        brand="Incident Logger"
    )

    pdf_io = BytesIO()
    pisa.CreatePDF(src=html, dest=pdf_io)
    pdf_io.seek(0)
    filename = f"{number}.pdf"
    log_audit('EXPORT', kind.capitalize(), rid, f"{current_username()} exported {filename}")
    return send_file(pdf_io, mimetype="application/pdf", as_attachment=True, download_name=filename)


# --- Attachments: download & bundle (PDF + attachments) ---
@app.get('/incidents/<int:rid>/attachments/<int:aid>/download', endpoint='download_incident_attachment')
@login_required
def download_incident_attachment(rid, aid):
    rec = Incident.query.get_or_404(rid)
    att = IncidentAttachment.query.filter_by(id=aid, incident_id=rid).first_or_404()
    path = os.path.join(UPLOAD_DIR, att.stored_path)
    if not os.path.exists(path):
        abort(404)
    log_audit('EXPORT', 'Incident', rid, f"{current_username()} downloaded attachment {att.original_name} for {rec.number}")
    return send_file(path, as_attachment=True, download_name=att.original_name)

@app.get('/incidents/<int:rid>/attachments/<int:aid>/preview', endpoint='preview_incident_attachment')
@login_required
def preview_incident_attachment(rid, aid):
    att = IncidentAttachment.query.filter_by(id=aid, incident_id=rid).first_or_404()
    path = os.path.join(UPLOAD_DIR, att.stored_path)
    if not os.path.exists(path):
        abort(404)
    # Best-effort content type
    ctype = att.content_type or ''
    if not ctype or ctype == 'application/octet-stream':
        ext = att.original_name.rsplit('.', 1)[-1].lower() if '.' in att.original_name else ''
        if ext in ('pdf',):
            ctype = 'application/pdf'
        elif ext in ('png','jpg','jpeg','gif','bmp','webp','tiff'):
            ctype = f'image/{ "jpeg" if ext in ("jpg","jpeg") else ext }'
        elif ext in ('txt','log','csv','json'):
            ctype = 'text/plain'
        else:
            ctype = 'application/octet-stream'
    log_audit('VIEW', 'Incident', rid, f"{current_username()} previewed attachment {att.original_name} for {att.incident_id}")
    return send_file(path, mimetype=ctype, as_attachment=False, download_name=att.original_name)

@app.get('/records/<kind>/<int:rid>/bundle', endpoint='bundle_record_with_attachments')
@login_required
def bundle_record_with_attachments(kind, rid):
    if kind != 'incident':
        abort(404)
    rec = Incident.query.get_or_404(rid)

    # Build PDF (same content as export_record_pdf)
    rev_raw = (rec.reviewer or '').strip().upper()
    reviewer_display = rev_raw if rev_raw in ('IM','SDM') else '— not assigned —'
    rows = [
        ("Number", rec.number),
        ("Date", fmt_date(rec.date)),
        ("System/Channel", rec.channel_or_system),
        ("Incident Narrative", rec.incident),
        ("Time of Incident", rec.time_of_incident or ""),
        ("Time of Resolution", rec.time_of_resolution or ""),
            ("Date of Resolution", fmt_date(rec.date_of_resolution)),
        ("Root Cause", rec.root_cause or ""),
        ("Impact", rec.impact or ""),
        ("Corrective Action", rec.corrective_action or ""),
        ("Corrective Action By", rec.corrective_action_by or ""),
        ("Reviewer", reviewer_display),
    ]
    if rev_raw == 'IM':
        rows += [("IM Comment", rec.im_comments or "Pending — awaiting IM input"),
                 ("IM Signature", rec.im_signature or "Pending")]
    elif rev_raw == 'SDM':
        rows += [("SDM Comment", rec.sdm_comments or "Pending — awaiting SDM input"),
                 ("SDM Signature", rec.sdm_signature or "Pending")]
    rows += [("Governance Comments", rec.governance_comments or ""),
             ("Governance Signature", rec.governance_signature or "")]

    html = render_template(
        'pdf_exec.html',
        title=f"Incident Report — {rec.number}",
        rows=rows,
        kind='incident',
        rid=rec.id,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        brand="Incident Logger"
    )
    pdf_io = BytesIO()
    pisa.CreatePDF(src=html, dest=pdf_io)
    pdf_io.seek(0)

    # Create zip bundle
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{rec.number}.pdf", pdf_io.read())
        # add attachments
        atts = IncidentAttachment.query.filter_by(incident_id=rec.id).all()
        if atts:
            for a in atts:
                p = os.path.join(UPLOAD_DIR, a.stored_path)
                if os.path.exists(p):
                    # put under attachments/ using original filename (disambiguated by id)
                    arcname = f"attachments/{a.id}_{a.original_name}"
                    with open(p, 'rb') as fh:
                        z.writestr(arcname, fh.read())
    buf.seek(0)
    fname = f"{rec.number}_bundle.zip"
    log_audit('EXPORT', 'Incident', rid, f"{current_username()} downloaded bundle (PDF + attachments) for {rec.number}")
    return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=fname)
# -------------------------
# Executive View page – with pending banners (incl. GM)
# -------------------------
@app.get('/records/<kind>/<int:rid>/view')
@login_required
def record_view(kind, rid):
    if kind == 'incident':
        rec = Incident.query.get_or_404(rid)
        title = f"Incident Report — {rec.number}"

        rev_raw = (rec.reviewer or '').strip().upper()
        reviewer_display = rev_raw if rev_raw in ('IM','SDM') else '— not assigned —'

        # Base rows
        rows = [
            ("Number", rec.number),
            ("Date", fmt_date(rec.date)),
            ("System/Channel", rec.channel_or_system),
            ("Incident Narrative", rec.incident),
            ("Time of Incident", rec.time_of_incident or ""),
            ("Time of Resolution", rec.time_of_resolution or ""),
            ("Date of Resolution", fmt_date(rec.date_of_resolution)),
            ("Root Cause", rec.root_cause or ""),
            ("Impact", rec.impact or ""),
            ("Corrective Action", rec.corrective_action or ""),
            ("Corrective Action By", rec.corrective_action_by or ""),
            ("Reviewer", reviewer_display),
        ]

        # Status banner logic
        pending_banner = ""
        if rev_raw == 'IM':
            im_comment_val = rec.im_comments or "Pending — awaiting IM input"
            im_sig_val     = rec.im_signature or "Pending"
            rows += [("IM Comment", im_comment_val), ("IM Signature", im_sig_val)]
            if not rec.im_comments or not rec.im_signature:
                pending_banner = "Pending: IM to enter comments"
        elif rev_raw == 'SDM':
            sdm_comment_val = rec.sdm_comments or "Pending — awaiting SDM input"
            sdm_sig_val     = rec.sdm_signature or "Pending"
            rows += [("SDM Comment", sdm_comment_val), ("SDM Signature", sdm_sig_val)]
            if not rec.sdm_comments or not rec.sdm_signature:
                pending_banner = "Pending: SDM to enter comments"
        else:
            pending_banner = "Pending: assign a reviewer"

        complete = is_incident_complete(rec)

        attachments = IncidentAttachment.query.filter_by(incident_id=rec.id).all()
        current_name = current_full_name_or_username()
        role = (session.get('role') or '').lower()
        can_edit = (role in ['ne','sd']) and ((rec.incident_logger or '').strip() == current_name) and (not reviewer_has_commented(rec))
        # Reviewer done, GM still needs to comment
        if not pending_banner and not complete and gm_can_comment(rec):
            pending_banner = "Pending: GM comment"

        # GM (Governance) rows always
        rows += [
            ("Governance Comments", rec.governance_comments or ""),
            ("Governance Signature", rec.governance_signature or ""),
        ]

        return render_template('record_view.html',
                               title=title, rows=rows, kind=kind, rid=rid,
                               number=rec.number, date=fmt_date(rec.date),
                               system=rec.channel_or_system, logger=rec.incident_logger,
                               complete=complete, pending_banner=pending_banner,
                               attachments=attachments, can_edit=bool(can_edit))
    else:
        abort(404)

# -------------------------
# Error handlers
# -------------------------
@app.errorhandler(403)
def forbidden(_):
    return make_response(
        render_template('base.html', title='Forbidden') +
        "<div class='container mt-4'><div class='alert alert-warning'>Forbidden.</div></div>", 403)

# -------------------------
# Run (dev server)
# -------------------------
if __name__ == '__main__':
    # In production run with a real WSGI server and HTTPS; cookies secure via env.
    app.run(debug=True)
