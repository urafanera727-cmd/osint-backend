ion — License Key Backend
Система лицензионных ключей.

Endpoints:
  POST /activate          — активация ключа (лоудер)
  POST /verify            — проверка сессии (лоудер при каждом запуске)
  POST /admin/genkey      — генерация ключа (ты)
  GET  /admin/keys        — список всех ключей
  POST /admin/revokekey   — отозвать ключ
  POST /admin/reset_hwid  — сбросить HWID ключа
"""

import os, secrets, datetime, string
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

# ── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./osint.db")
ADMIN_KEY    = os.getenv("ADMIN_KEY", "changeme")
DOWNLOAD_URL = os.getenv("DOWNLOAD_URL", "https://example.com/app.exe")
TOKEN_TTL_H  = int(os.getenv("TOKEN_TTL_H", "720"))

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine  = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
Session = sessionmaker(bind=engine)
Base    = declarative_base()

# ── Models ────────────────────────────────────────────────────────────────────
class LicenseKey(Base):
    __tablename__ = "license_keys"
    id         = Column(Integer, primary_key=True)
    key        = Column(String(32), unique=True, nullable=False)  # XXXX-XXXX-XXXX-XXXX
    hwid       = Column(String(128), nullable=True)               # привязывается при первом входе
    token      = Column(String(128), nullable=True)               # сессионный токен
    token_exp  = Column(DateTime, nullable=True)
    active     = Column(Boolean, default=True)                    # можно отозвать
    note       = Column(String(256), nullable=True)               # заметка (имя покупателя итд)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    used_at    = Column(DateTime, nullable=True)

Base.metadata.create_all(engine)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Helpers ───────────────────────────────────────────────────────────────────
def now():
    return datetime.datetime.utcnow()

def gen_license_key():
    """Генерирует ключ вида XXXX-XXXX-XXXX-XXXX (только заглавные буквы и цифры)"""
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return '-'.join(parts)

def chk_admin(k):
    if k != ADMIN_KEY:
        raise HTTPException(403, "Нет доступа")

# ── Schemas ───────────────────────────────────────────────────────────────────
class ActivateReq(BaseModel):
    key:  str
    hwid: str

class VerifyReq(BaseModel):
    token: str
    hwid:  str

class GenKeyReq(BaseModel):
    note:  str = ""   # имя покупателя или любая заметка

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/activate")
def activate(req: ActivateReq):
    """
    Активация ключа из лоудера.
    - Проверяет что ключ существует и активен
    - При первом входе привязывает HWID
    - Если HWID уже привязан к другому железу — отказ
    - Возвращает токен + download_url
    """
    db = Session()
    try:
        key = req.key.strip().upper().replace(" ", "")
        lic = db.query(LicenseKey).filter_by(key=key).first()

        if not lic:
            raise HTTPException(404, "Ключ не найден")
        if not lic.active:
            raise HTTPException(403, "Ключ отозван или заблокирован")

        hwid = req.hwid.strip()

        # HWID проверка
        if lic.hwid and lic.hwid != hwid:
            raise HTTPException(403,
                "Ключ привязан к другому устройству. "
                "Для смены устройства обратитесь к администратору.")

        # Выдаём токен
        token = secrets.token_hex(32)
        exp   = now() + datetime.timedelta(hours=TOKEN_TTL_H)

        lic.hwid      = hwid
        lic.token     = token
        lic.token_exp = exp
        lic.used_at   = now()
        db.commit()

        return {
            "ok":           True,
            "token":        token,
            "expires_at":   exp.isoformat(),
            "download_url": DOWNLOAD_URL
        }
    finally:
        db.close()

@app.post("/verify")
def verify(req: VerifyReq):
    """Проверка сессии при каждом запуске лоудера."""
    db = Session()
    try:
        lic = db.query(LicenseKey).filter_by(token=req.token).first()
        if not lic:
            raise HTTPException(401, "Токен недействителен")
        if lic.hwid != req.hwid.strip():
            raise HTTPException(403, "HWID не совпадает")
        if lic.token_exp and lic.token_exp < now():
            raise HTTPException(401, "Токен истёк")
        if not lic.active:
            raise HTTPException(403, "Ключ заблокирован")
        return {"ok": True, "download_url": DOWNLOAD_URL}
    finally:
        db.close()

# ── Admin ─────────────────────────────────────────────────────────────────────

@app.post("/admin/genkey")
def admin_genkey(req: GenKeyReq, x_admin_key: str = Header(...)):
    """Генерация нового лицензионного ключа."""
    chk_admin(x_admin_key)
    db = Session()
    try:
        # Генерируем уникальный ключ
        for _ in range(10):
            key = gen_license_key()
            if not db.query(LicenseKey).filter_by(key=key).first():
                break
        lic = LicenseKey(key=key, note=req.note)
        db.add(lic)
        db.commit()
        return {"ok": True, "key": key, "note": req.note}
    finally:
        db.close()

@app.get("/admin/keys")
def admin_keys(x_admin_key: str = Header(...)):
    """Список всех ключей."""
    chk_admin(x_admin_key)
    db = Session()
    try:
        keys = db.query(LicenseKey).order_by(LicenseKey.created_at.desc()).all()
        return [{
            "id":         k.id,
            "key":        k.key,
            "active":     k.active,
            "hwid":       k.hwid,
            "note":       k.note,
            "created_at": str(k.created_at),
            "used_at":    str(k.used_at) if k.used_at else None
        } for k in keys]
    finally:
        db.close()

@app.post("/admin/revokekey")
def admin_revokekey(key: str, x_admin_key: str = Header(...)):
    """Отозвать ключ."""
    chk_admin(x_admin_key)
    db = Session()
    try:
        lic = db.query(LicenseKey).filter_by(key=key.upper()).first()
        if not lic:
            raise HTTPException(404, "Ключ не найден")
        lic.active = False
        lic.token  = None
        db.commit()
        return {"ok": True, "message": f"Ключ {key} отозван"}
    finally:
        db.close()

@app.post("/admin/reset_hwid")
def admin_reset_hwid(key: str, x_admin_key: str = Header(...)):
    """Сбросить HWID — юзер сможет привязать новое устройство."""
    chk_admin(x_admin_key)
    db = Session()
    try:
        lic = db.query(LicenseKey).filter_by(key=key.upper()).first()
        if not lic:
            raise HTTPException(404, "Ключ не найден")
        lic.hwid  = None
        lic.token = None
        db.commit()
        return {"ok": True, "message": f"HWID сброшен для ключа {key}"}
    finally:
        db.close()
