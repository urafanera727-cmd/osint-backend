import os, secrets, datetime, hashlib
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./osint.db")
ADMIN_KEY    = os.getenv("ADMIN_KEY", "changeme")
DOWNLOAD_URL = os.getenv("DOWNLOAD_URL", "https://example.com/app.exe")
TOKEN_TTL_H  = int(os.getenv("TOKEN_TTL_H", "720"))

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine  = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
Session = sessionmaker(bind=engine)
Base    = declarative_base()
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True)
    email         = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    hwid          = Column(String, nullable=True)
    token         = Column(String, nullable=True)
    token_exp     = Column(DateTime, nullable=True)
    approved      = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(engine)

app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class RegisterReq(BaseModel):
    email: str
    password: str

class LoginReq(BaseModel):
    email: str
    password: str
    hwid: str

class VerifyReq(BaseModel):
    token: str
    hwid: str

def now(): return datetime.datetime.utcnow()

@app.get("/health")
def health(): return {"ok": True}

@app.post("/register")
def register(req: RegisterReq):
    db = Session()
    try:
        if db.query(User).filter_by(email=req.email).first():
            raise HTTPException(400, "Email уже зарегистрирован")
        if len(req.password) < 6:
            raise HTTPException(400, "Пароль минимум 6 символов")
        db.add(User(email=req.email, password_hash=pwd_ctx.hash(req.password)))
        db.commit()
        return {"ok": True, "message": "Аккаунт создан. Ожидайте активации."}
    finally:
        db.close()

@app.post("/login")
def login(req: LoginReq):
    db = Session()
    try:
        u = db.query(User).filter_by(email=req.email).first()
        if not u or not pwd_ctx.verify(req.password, u.password_hash):
            raise HTTPException(401, "Неверный email или пароль")
        if not u.approved:
            raise HTTPException(403, "Аккаунт не активирован")
        if u.hwid and u.hwid != req.hwid.strip():
            raise HTTPException(403, "Аккаунт привязан к другому устройству")
        token = secrets.token_hex(32)
        exp   = now() + datetime.timedelta(hours=TOKEN_TTL_H)
        u.hwid = req.hwid.strip()
        u.token = token
        u.token_exp = exp
        db.commit()
        return {"ok": True, "token": token, "download_url": DOWNLOAD_URL}
    finally:
        db.close()

@app.post("/verify")
def verify(req: VerifyReq):
    db = Session()
    try:
        u = db.query(User).filter_by(token=req.token).first()
        if not u: raise HTTPException(401, "Токен недействителен")
        if u.hwid != req.hwid.strip(): raise HTTPException(403, "HWID не совпадает")
        if u.token_exp and u.token_exp < now(): raise HTTPException(401, "Токен истёк")
        if not u.approved: raise HTTPException(403, "Аккаунт заблокирован")
        return {"ok": True, "email": u.email, "download_url": DOWNLOAD_URL}
    finally:
        db.close()

def chk(k): 
    if k != ADMIN_KEY: raise HTTPException(403, "Нет доступа")

@app.get("/admin/users")
def admin_users(x_admin_key: str = Header(...)):
    chk(x_admin_key)
    db = Session()
    try:
        return [{"id":u.id,"email":u.email,"approved":u.approved,"hwid":u.hwid} for u in db.query(User).all()]
    finally:
        db.close()

@app.post("/admin/approve")
def admin_approve(email: str, x_admin_key: str = Header(...)):
    chk(x_admin_key)
    db = Session()
    try:
        u = db.query(User).filter_by(email=email).first()
        if not u: raise HTTPException(404, "Не найден")
        u.approved = True
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.post("/admin/revoke")
def admin_revoke(email: str, x_admin_key: str = Header(...)):
    chk(x_admin_key)
    db = Session()
    try:
        u = db.query(User).filter_by(email=email).first()
        if not u: raise HTTPException(404, "Не найден")
        u.approved = False
        u.token = None
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.post("/admin/reset_hwid")
def admin_reset_hwid(email: str, x_admin_key: str = Header(...)):
    chk(x_admin_key)
    db = Session()
    try:
        u = db.query(User).filter_by(email=email).first()
        if not u: raise HTTPException(404, "Не найден")
        u.hwid = None
        u.token = None
        db.commit()
        return {"ok": True}
    finally:
        db.close()
