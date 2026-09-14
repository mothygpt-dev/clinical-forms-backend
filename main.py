from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APP_VERSION = "0.7.0"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
ADMIN_USERNAME = os.getenv("CLINICAL_FORMS_ADMIN_USER", "center").strip() or "center"
ADMIN_PASSWORD = os.getenv("CLINICAL_FORMS_ADMIN_PASSWORD", "").strip()
ADMIN_NAME = os.getenv("CLINICAL_FORMS_ADMIN_NAME", "مركز شعبة الصيدلة").strip() or "مركز شعبة الصيدلة"
ADMIN_DEPARTMENT = os.getenv("CLINICAL_FORMS_ADMIN_DEPARTMENT", "شعبة الصيدلة - مستشفى الموصل العام").strip()
ADMIN_PHONE = os.getenv("CLINICAL_FORMS_ADMIN_PHONE", "").strip()

WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WA_ADMIN_TO = "".join(ch for ch in os.getenv("WHATSAPP_ADMIN_TO", "") if ch.isdigit())
WA_GRAPH_VERSION = os.getenv("WHATSAPP_GRAPH_VERSION", "v23.0").strip() or "v23.0"
WA_TEMPLATE_NAME = os.getenv("WHATSAPP_TEMPLATE_NAME", "").strip()
WA_TEMPLATE_LANGUAGE = os.getenv("WHATSAPP_TEMPLATE_LANGUAGE", "ar").strip() or "ar"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("clinical-forms")
app = FastAPI(title="Mosul General Hospital Rational Drug Use Forms API", version=APP_VERSION)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_phone(value: str) -> str:
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("07") and len(digits) == 11:
        digits = "964" + digits[1:]
    elif digits.startswith("7") and len(digits) == 10:
        digits = "964" + digits
    return digits


def valid_iraqi_phone(value: str) -> bool:
    p = normalize_phone(value)
    return len(p) == 13 and p.startswith("9647") and p.isdigit()


def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 250_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    _, candidate = hash_password(password, salt_hex)
    return secrets.compare_digest(candidate, digest_hex)


def conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=False)


def init_schema() -> None:
    if not DATABASE_URL:
        log.warning("DATABASE_URL not configured; API starts in setup-required state")
        return
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    department TEXT NOT NULL DEFAULT '',
                    phone TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL CHECK(role IN ('ADMIN','SUPERVISOR','SENDER')),
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_admin
                ON users(role) WHERE role='ADMIN' AND active=TRUE
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS forms (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL CHECK(type IN ('ALBUMIN','ACTILYSE','MEROPENEM')),
                    payload_json JSONB NOT NULL,
                    submitted_by TEXT NOT NULL REFERENCES users(username),
                    submitted_by_name TEXT NOT NULL,
                    submitted_by_phone TEXT NOT NULL,
                    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    status TEXT NOT NULL DEFAULT 'Submitted'
                )
            """)
        c.commit()
    ensure_admin_if_configured()


def ensure_admin_if_configured() -> bool:
    if not DATABASE_URL:
        return False
    normalized_phone = normalize_phone(ADMIN_PHONE)
    ready = len(ADMIN_PASSWORD) >= 10 and valid_iraqi_phone(normalized_phone)
    if not ready:
        return False
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE role='ADMIN' AND active=TRUE LIMIT 1")
            admin = cur.fetchone()
            if not admin:
                salt, digest = hash_password(ADMIN_PASSWORD)
                cur.execute(
                    """INSERT INTO users(username,display_name,department,phone,role,salt,password_hash,active)
                       VALUES(%s,%s,%s,%s,'ADMIN',%s,%s,TRUE)""",
                    (ADMIN_USERNAME, ADMIN_NAME, ADMIN_DEPARTMENT, normalized_phone, salt, digest),
                )
            else:
                cur.execute(
                    "UPDATE users SET display_name=%s,department=%s,phone=%s WHERE username=%s",
                    (ADMIN_NAME, ADMIN_DEPARTMENT, normalized_phone, admin["username"]),
                )
        c.commit()
    return True


@app.on_event("startup")
def startup() -> None:
    init_schema()


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    phone: str = Field(min_length=10, max_length=24)


class FormIn(BaseModel):
    type: str
    payload: dict[str, str]


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=120)
    department: str = Field(default="", max_length=160)
    phone: str = Field(min_length=10, max_length=24)
    role: str = "SENDER"


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = bearer_token(authorization)
    if not DATABASE_URL:
        raise HTTPException(503, "Server database is not configured")
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("""SELECT u.* FROM sessions s JOIN users u ON u.username=s.username
                           WHERE s.token=%s AND u.active=TRUE""", (token,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(401, "Invalid session")
    return row


def user_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": row["username"], "display_name": row["display_name"],
        "department": row["department"], "phone": row["phone"],
        "role": row["role"], "active": bool(row.get("active", True)),
    }


def form_dict(row: dict[str, Any]) -> dict[str, Any]:
    payload = row["payload_json"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    submitted_at = row["submitted_at"]
    if hasattr(submitted_at, "isoformat"):
        submitted_at = submitted_at.isoformat()
    return {
        "id": row["id"], "type": row["type"], "payload": payload,
        "submitted_by": row["submitted_by"], "submitted_by_name": row["submitted_by_name"],
        "submitted_by_phone": row["submitted_by_phone"], "submitted_at": submitted_at,
        "status": row["status"],
    }


def whatsapp_target() -> str:
    configured = normalize_phone(WA_ADMIN_TO) if WA_ADMIN_TO else normalize_phone(ADMIN_PHONE)
    return configured if valid_iraqi_phone(configured) else ""


def whatsapp_enabled() -> bool:
    return bool(WA_ACCESS_TOKEN and WA_PHONE_NUMBER_ID and whatsapp_target())


def send_whatsapp_notification(form_id: str, form_type: str, sender_name: str, sender_phone: str) -> None:
    if not whatsapp_enabled():
        return
    endpoint = f"https://graph.facebook.com/{WA_GRAPH_VERSION}/{WA_PHONE_NUMBER_ID}/messages"
    if WA_TEMPLATE_NAME:
        payload: dict[str, Any] = {
            "messaging_product": "whatsapp", "to": whatsapp_target(), "type": "template",
            "template": {
                "name": WA_TEMPLATE_NAME, "language": {"code": WA_TEMPLATE_LANGUAGE},
                "components": [{"type": "body", "parameters": [
                    {"type": "text", "text": sender_name},
                    {"type": "text", "text": form_type},
                    {"type": "text", "text": form_id},
                ]}],
            },
        }
    else:
        payload = {
            "messaging_product": "whatsapp", "to": whatsapp_target(), "type": "text",
            "text": {"preview_url": False, "body": (
                "مستشفى الموصل العام - شعبة الصيدلة\n"
                "استمارة جديدة ضمن برنامج الاستخدام الرشيد للدواء\n"
                f"النوع: {form_type}\nالمرسل: {sender_name}\n"
                f"رقم المرسل: +{sender_phone}\nForm ID: {form_id}\n"
                "افتح تطبيق المركز لمراجعة التفاصيل."
            )},
        }
    req = urllib.request.Request(endpoint, data=json.dumps(payload, ensure_ascii=False).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {WA_ACCESS_TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            log.info("WhatsApp notification sent for %s HTTP %s", form_id, response.status)
    except Exception as exc:
        log.warning("WhatsApp notification failed for %s: %s", form_id, exc)


@app.get("/health")
def health() -> dict[str, Any]:
    db_ok = False
    if DATABASE_URL:
        try:
            with conn() as c:
                with c.cursor() as cur:
                    cur.execute("SELECT 1")
                    db_ok = cur.fetchone() is not None
        except Exception:
            db_ok = False
    center_ready = bool(DATABASE_URL and len(ADMIN_PASSWORD) >= 10 and valid_iraqi_phone(ADMIN_PHONE))
    return {"status": "ok" if db_ok else "setup_required", "version": APP_VERSION,
            "database_ready": db_ok, "center_ready": center_ready,
            "whatsapp_enabled": whatsapp_enabled()}


@app.post("/api/login")
def login(data: LoginIn) -> dict[str, Any]:
    if not DATABASE_URL:
        raise HTTPException(503, "Server database is not configured")
    ensure_admin_if_configured()
    normalized_phone = normalize_phone(data.phone)
    if not valid_iraqi_phone(normalized_phone):
        raise HTTPException(401, "Invalid login credentials")
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username=%s AND phone=%s AND active=TRUE",
                        (data.username.strip(), normalized_phone))
            user = cur.fetchone()
            if not user or not verify_password(data.password, user["salt"], user["password_hash"]):
                raise HTTPException(401, "Invalid login credentials")
            token = secrets.token_urlsafe(48)
            cur.execute("INSERT INTO sessions(token,username) VALUES(%s,%s)", (token, user["username"]))
        c.commit()
    result = user_dict(user); result["token"] = token
    return result


@app.get("/api/me")
def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return user_dict(user)


@app.post("/api/logout")
def logout(authorization: str | None = Header(default=None)) -> dict[str, str]:
    token = bearer_token(authorization)
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token=%s", (token,))
        c.commit()
    return {"status": "logged_out"}


@app.post("/api/forms")
def create_form(data: FormIn, background_tasks: BackgroundTasks,
                user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if data.type not in {"ALBUMIN", "ACTILYSE", "MEROPENEM"}:
        raise HTTPException(400, "Unknown form type")
    if not valid_iraqi_phone(user["phone"]):
        raise HTTPException(409, "Account does not have a valid mandatory WhatsApp number")
    form_id = f"{data.type[:3]}-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("""INSERT INTO forms(id,type,payload_json,submitted_by,submitted_by_name,submitted_by_phone)
                           VALUES(%s,%s,%s::jsonb,%s,%s,%s) RETURNING *""",
                        (form_id, data.type, json.dumps(data.payload, ensure_ascii=False), user["username"],
                         user["display_name"], user["phone"]))
            row = cur.fetchone()
        c.commit()
    background_tasks.add_task(send_whatsapp_notification, form_id, data.type, user["display_name"], user["phone"])
    return form_dict(row)


@app.get("/api/forms")
def list_forms(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, list[dict[str, Any]]]:
    with conn() as c:
        with c.cursor() as cur:
            if user["role"] == "ADMIN":
                cur.execute("SELECT * FROM forms ORDER BY submitted_at DESC")
            else:
                cur.execute("SELECT * FROM forms WHERE submitted_by=%s ORDER BY submitted_at DESC", (user["username"],))
            rows = cur.fetchall()
    return {"items": [form_dict(r) for r in rows]}


@app.get("/api/users")
def list_users(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, list[dict[str, Any]]]:
    if user["role"] != "ADMIN":
        raise HTTPException(403, "Admin only")
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("""SELECT username,display_name,department,phone,role,active FROM users
                           WHERE role='SENDER' ORDER BY display_name,username""")
            rows = cur.fetchall()
    return {"items": [user_dict(r) for r in rows]}


@app.post("/api/users")
def create_user(data: UserIn, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, str]:
    if user["role"] != "ADMIN":
        raise HTTPException(403, "Admin only")
    if data.role != "SENDER":
        raise HTTPException(400, "Only sender accounts can be created")
    phone = normalize_phone(data.phone)
    if not valid_iraqi_phone(phone):
        raise HTTPException(400, "A valid Iraqi WhatsApp number is mandatory")
    salt, digest = hash_password(data.password)
    try:
        with conn() as c:
            with c.cursor() as cur:
                cur.execute("""INSERT INTO users(username,display_name,department,phone,role,salt,password_hash,active)
                               VALUES(%s,%s,%s,%s,'SENDER',%s,%s,TRUE)""",
                            (data.username.strip(), data.display_name.strip(), data.department.strip(), phone, salt, digest))
            c.commit()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Username or WhatsApp number already exists")
    return {"status": "created", "username": data.username.strip()}


@app.get("/api/admin/notification-status")
def notification_status(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user["role"] != "ADMIN":
        raise HTTPException(403, "Admin only")
    target = whatsapp_target()
    return {"whatsapp_enabled": whatsapp_enabled(),
            "target": f"***{target[-4:]}" if len(target) >= 4 else "",
            "template_mode": bool(WA_TEMPLATE_NAME)}
