"""
OSINT Station — License Backend
FastAPI + SQLite (в проде заменить на PostgreSQL через DATABASE_URL env)

Endpoints:
  POST /register        — регистрация (email + password)
  POST /login           — логин, привязка HWID, возврат токена + download_url
  GET  /verify          — проверка токена (лоудер дёргает при каждом запуске)
  POST /admin/approve   — одобрить юзера (только ты, через admin_key)
  POST /admin/revoke    — отозвать доступ
  GET  /admin/users     — список всех юзеров
"""

import os, hashlib, secrets, datetime
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import databases, sqlalchemy
from passlib.context import CryptContext

# ── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL  = os.getenv("DATABASE_URL", "sqlite:///./osint.db")
ADMIN_KEY     = os.getenv("ADMIN_KEY", "changeme-secret-admin-key")
DOWNLOAD_URL  = os.getenv("DOWNLOAD_URL", "https://github.com/YOURNAME/YOURREPO/releases/download/v9.0.0/OSINT-Visual-Station-9.0.0-Windows-x64.exe")
TOKEN_TTL_H   = int(os.getenv("TOKEN_TTL_H", "720"))   # 30 дней

# ── DB setup ──────────────────────────────────────────────────────────────────
# Для Railway PostgreSQL DATABASE_URL будет автоматически подставлен
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

database  = databases.Database(DATABASE_URL)
metadata  = sqlalchemy.MetaData()

users = sqlalchemy.Table("users", metadata,
    sqlalchemy.Column("id",           sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("email",        sqlalchemy.String(255), unique=True, nullable=False),
    sqlalchemy.Column("password_hash",sqlalchemy.String(255), nullable=False),
    sqlalchemy.Column("hwid",         sqlalchemy.String(255), nullable=True),
    sqlalchemy.Column("token",        sqlalchemy.String(255), nullable=True),
    sqlalchemy.Column("token_exp",    sqlalchemy.DateTime,    nullable=True),
    sqlalchemy.Column("approved",     sqlalchemy.Boolean,     default=False),
    sqlalchemy.Column("created_at",   sqlalchemy.DateTime,    default=datetime.datetime.utcnow),
)

engine = sqlalchemy.create_engine(
    DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://")
    if "postgresql" in DATABASE_URL
    else DATABASE_URL
)
metadata.create_all(engine)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="OSINT Station License API", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Schemas ───────────────────────────────────────────────────────────────────
class RegisterReq(BaseModel):
    email:    EmailStr
    password: str

class LoginReq(BaseModel):
    email:    EmailStr
    password: str
    hwid:     str          # собирается лоудером автоматически

class VerifyReq(BaseModel):
    token: str
    hwid:  str

# ── Helpers ───────────────────────────────────────────────────────────────────
def now():
    return datetime.datetime.utcnow()

def make_token():
    return secrets.token_hex(32)

def token_exp():
    return now() + datetime.timedelta(hours=TOKEN_TTL_H)

# ── Lifecycle ─────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/register")
async def register(req: RegisterReq):
    """Регистрация. Аккаунт создаётся с approved=False — ты одобряешь вручную."""
    existing = await database.fetch_one(
        users.select().where(users.c.email == req.email))
    if existing:
        raise HTTPException(400, "Email уже зарегистрирован")

    if len(req.password) < 6:
        raise HTTPException(400, "Пароль минимум 6 символов")

    pw_hash = pwd_ctx.hash(req.password)
    await database.execute(users.insert().values(
        email=req.email,
        password_hash=pw_hash,
        approved=False,
        created_at=now()
    ))
    return {"ok": True, "message": "Аккаунт создан. Ожидайте активации."}


@app.post("/login")
async def login(req: LoginReq):
    """
    Логин из лоудера.
    - Проверяет пароль
    - Проверяет approved
    - Привязывает HWID при первом входе
    - Если HWID уже привязан к другому устройству — отказ
    - Возвращает токен + download_url
    """
    row = await database.fetch_one(
        users.select().where(users.c.email == req.email))

    if not row or not pwd_ctx.verify(req.password, row["password_hash"]):
        raise HTTPException(401, "Неверный email или пароль")

    if not row["approved"]:
        raise HTTPException(403, "Аккаунт не активирован. Обратитесь к администратору.")

    hwid = req.hwid.strip()

    # HWID проверка
    if row["hwid"] and row["hwid"] != hwid:
        raise HTTPException(403,
            "Аккаунт привязан к другому устройству. "
            "Для смены устройства обратитесь к администратору.")

    # Новый токен
    token = make_token()
    exp   = token_exp()

    await database.execute(
        users.update()
        .where(users.c.email == req.email)
        .values(hwid=hwid, token=token, token_exp=exp)
    )

    return {
        "ok":           True,
        "token":        token,
        "expires_at":   exp.isoformat(),
        "download_url": DOWNLOAD_URL
    }


@app.post("/verify")
async def verify(req: VerifyReq):
    """Лоудер дёргает при каждом запуске — проверить что токен ещё живой и HWID совпадает."""
    row = await database.fetch_one(
        users.select().where(users.c.token == req.token))

    if not row:
        raise HTTPException(401, "Токен недействителен")

    if row["hwid"] != req.hwid.strip():
        raise HTTPException(403, "HWID не совпадает")

    if row["token_exp"] and row["token_exp"] < now():
        raise HTTPException(401, "Токен истёк, войдите снова")

    if not row["approved"]:
        raise HTTPException(403, "Аккаунт заблокирован")

    return {"ok": True, "email": row["email"], "download_url": DOWNLOAD_URL}


# ── Admin routes ──────────────────────────────────────────────────────────────

def check_admin(x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Нет доступа")

@app.get("/admin/users")
async def admin_users(x_admin_key: str = Header(...)):
    check_admin(x_admin_key)
    rows = await database.fetch_all(users.select().order_by(users.c.created_at.desc()))
    return [{"id": r["id"], "email": r["email"], "approved": r["approved"],
             "hwid": r["hwid"], "created_at": str(r["created_at"])} for r in rows]

@app.post("/admin/approve")
async def admin_approve(email: str, x_admin_key: str = Header(...)):
    """Одобрить юзера — после этого он сможет войти."""
    check_admin(x_admin_key)
    row = await database.fetch_one(users.select().where(users.c.email == email))
    if not row:
        raise HTTPException(404, "Юзер не найден")
    await database.execute(
        users.update().where(users.c.email == email).values(approved=True))
    return {"ok": True, "message": f"{email} одобрен"}

@app.post("/admin/revoke")
async def admin_revoke(email: str, x_admin_key: str = Header(...)):
    """Отозвать доступ — юзер не сможет войти и токен станет невалидным."""
    check_admin(x_admin_key)
    row = await database.fetch_one(users.select().where(users.c.email == email))
    if not row:
        raise HTTPException(404, "Юзер не найден")
    await database.execute(
        users.update().where(users.c.email == email)
        .values(approved=False, token=None, token_exp=None))
    return {"ok": True, "message": f"{email} заблокирован"}

@app.post("/admin/reset_hwid")
async def admin_reset_hwid(email: str, x_admin_key: str = Header(...)):
    """Сбросить HWID — юзер сможет привязать новое устройство."""
    check_admin(x_admin_key)
    await database.execute(
        users.update().where(users.c.email == email)
        .values(hwid=None, token=None, token_exp=None))
    return {"ok": True, "message": f"HWID сброшен для {email}"}

@app.get("/health")
async def health():
    return {"ok": True}
