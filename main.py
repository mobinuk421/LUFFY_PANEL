import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LUFFY-Gateway")

app = FastAPI(title="LUFFY PANEL", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory State
connections: dict = {}
connection_sockets: dict = {}
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

# اضافه شدن تنظیمات سراسری پنل
SETTINGS: dict = {"clean_ip": ""} 

SESSION_COOKIE = "luffy_session"
SESSION_TTL = 60 * 60 * 24 * 7
DATA_FILE = "luffy_data.json"

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

# --- Data Persistence ---
def load_data():
    global LINKS, stats, SETTINGS
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
                LINKS = data.get("links", {})
                saved_stats = data.get("stats", {})
                SETTINGS = data.get("settings", {"clean_ip": ""})
                stats["total_bytes"] = saved_stats.get("total_bytes", 0)
                stats["total_requests"] = saved_stats.get("total_requests", 0)
                logger.info("LUFFY data loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading data: {e}")

async def save_data_loop():
    while True:
        await asyncio.sleep(60)
        async with LINKS_LOCK:
            data_to_save = {
                "links": LINKS,
                "stats": {"total_bytes": stats["total_bytes"], "total_requests": stats["total_requests"]},
                "settings": SETTINGS
            }
        try:
            await asyncio.to_thread(write_json, data_to_save)
        except Exception as e:
            logger.error(f"Error saving data: {e}")

def write_json(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)
# ------------------------

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    load_data()
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"LUFFY PANEL started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())
    asyncio.create_task(save_data_loop())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()
    data_to_save = {"links": LINKS, "stats": {"total_bytes": stats["total_bytes"], "total_requests": stats["total_requests"]}, "settings": SETTINGS}
    write_json(data_to_save)

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "LUFFY") -> str:
    domain = get_domain()
    # استفاده از آی‌پی تمیز ذخیره شده در پنل (اولویت اول)
    panel_clean_ip = SETTINGS.get("clean_ip")
    clean_ip = panel_clean_ip if panel_clean_ip else os.environ.get("CLEAN_IP", domain)
    
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{clean_ip}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid("default")
            LINKS[uid] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True}

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)

@app.get("/")
async def root():
    return {"service": "LUFFY PANEL", "version": "3.5", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

# API جدید برای دریافت و تغییر تنظیمات شبکه
@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    return SETTINGS

@app.patch("/api/settings")
async def update_settings(request: Request, _=Depends(require_auth)):
    body = await request.json()
    if "clean_ip" in body:
        SETTINGS["clean_ip"] = str(body["clean_ip"]).strip()
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    uid = generate_uuid(label)
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "active": True, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"LUFFY-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "active": data["active"], "created_at": data["created_at"], "vless_link": generate_vless_link(uid, remark=f"LUFFY-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    conn_id = secrets.token_urlsafe(8)
    connections[conn_id] = {"uuid": uuid, "connected_at": datetime.now().isoformat(), "bytes": 0}
    connection_sockets[conn_id] = websocket
    writer = None
    try:
        if not await check_quota(uuid, 0):
            await websocket.close(code=1008, reason="quota exceeded or link deleted"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        connections.pop(conn_id, None)
        connection_sockets.pop(conn_id, None)

# ----------------- HTML TEMPLATES (GLASSMORPHISM UI) -----------------

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LUFFY PANEL | Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#050505;--surface:rgba(25,25,25,0.6);--surface2:rgba(40,40,40,0.5);--border:rgba(255,255,255,0.08);--text:rgba(255,255,255,0.95);--text2:rgba(255,255,255,0.6);--text3:rgba(255,255,255,0.3);--primary:#ef4444;--primary-glow:rgba(239,68,68,0.25);--accent:#f59e0b;--error:#ef4444;--error-bg:rgba(239,68,68,0.1)}
html[data-theme="light"]{--bg:#f3f4f6;--surface:rgba(255,255,255,0.7);--surface2:rgba(240,240,240,0.6);--border:rgba(0,0,0,0.08);--text:rgba(0,0,0,0.9);--text2:rgba(0,0,0,0.6);--text3:rgba(0,0,0,0.3);--primary:#dc2626;--primary-glow:rgba(220,38,38,0.2);--accent:#ea580c;--error:#dc2626;--error-bg:rgba(220,38,38,0.08)}
body{font-family:'Inter',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .4s ease,color .4s ease;position:relative;overflow:hidden}
body::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle at 50% 30%, var(--primary-glow), transparent 40%);z-index:-1;animation:pulseBg 10s infinite alternate}
@keyframes pulseBg{0%{transform:scale(1)}100%{transform:scale(1.1)}}

.toolbar{position:fixed;top:24px;right:24px;display:flex;gap:8px;z-index:10}
.toolbar button{width:40px;height:40px;border-radius:12px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:600;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);transition:all .3s ease;box-shadow:0 4px 12px rgba(0,0,0,0.05)}
.toolbar button:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-2px)}

.login-page{width:100%;max-width:400px;padding:0 20px;animation:fadeUp 0.6s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(20px)}
@keyframes fadeUp{to{opacity:1;transform:translateY(0)}}
.login-card{background:var(--surface);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:24px;padding:48px 40px 40px;position:relative;box-shadow:0 12px 40px rgba(0,0,0,0.2), inset 0 1px 0 rgba(255,255,255,0.1)}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg, var(--primary), var(--accent));border-radius:24px 24px 0 0}

.brand{text-align:center;margin-bottom:40px}
.brand svg{margin-bottom:20px;filter:drop-shadow(0 8px 16px var(--primary-glow))}
.brand h1{font-size:26px;font-weight:800;letter-spacing:-0.03em;background:linear-gradient(90deg, var(--primary), var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand p{font-size:12px;color:var(--text2);margin-top:8px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase}

.form-group{margin-bottom:24px}
.form-group label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:10px;text-transform:uppercase;letter-spacing:0.05em}
.form-group input{width:100%;padding:14px 16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;color:var(--text);font-size:15px;font-family:inherit;outline:none;transition:all .3s ease;box-shadow:inset 0 2px 4px rgba(0,0,0,0.1)}
.form-group input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow), inset 0 2px 4px rgba(0,0,0,0.1)}
.form-group input::placeholder{color:var(--text3)}

.login-btn{width:100%;padding:14px;background:linear-gradient(135deg, var(--primary), var(--accent));border:none;border-radius:12px;color:#fff;font-size:15px;font-weight:700;font-family:inherit;cursor:pointer;transition:all .3s ease;letter-spacing:0.02em;box-shadow:0 8px 20px var(--primary-glow)}
.login-btn:hover{transform:translateY(-2px);box-shadow:0 12px 24px var(--primary-glow);filter:brightness(1.1)}
.login-btn:active{transform:translateY(0);box-shadow:0 4px 10px var(--primary-glow)}

.error-msg{background:var(--error-bg);border:1px solid rgba(239,68,68,0.2);color:var(--error);padding:12px 16px;border-radius:12px;font-size:13px;display:none;margin-bottom:24px;text-align:center;font-weight:600;backdrop-filter:blur(10px)}
.error-msg.show{display:block;animation:shake 0.4s cubic-bezier(.36,.07,.19,.97) both}
@keyframes shake{10%,90%{transform:translate3d(-1px,0,0)}20%,80%{transform:translate3d(2px,0,0)}30%,50%,70%{transform:translate3d(-3px,0,0)}40%,60%{transform:translate3d(3px,0,0)}}
</style>
</head>
<body>
<div class="toolbar">
  <button id="lang-toggle" onclick="cycleLang()" title="Language">EN</button>
  <button id="theme-toggle" onclick="toggleTheme()" title="Theme">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
  </button>
</div>
<div class="login-page">
  <div class="login-card">
    <div class="brand">
      <svg width="64" height="64" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="16" fill="url(#logo-grad)"/>
        <path d="M18 14h6v22h14v6H18V14z" fill="#fff" opacity="0.95"/>
        <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#ef4444"/><stop offset="1" stop-color="#f59e0b"/></linearGradient></defs>
      </svg>
      <h1>LUFFY</h1>
      <p>Premium Panel</p>
    </div>
    <div class="error-msg" id="err-box"></div>
    <form id="login-form">
      <div class="form-group">
        <label data-en="Password" data-fa="رمز عبور">Password</label>
        <input type="password" id="password" placeholder="Enter password" autofocus>
      </div>
      <button type="submit" class="login-btn" data-en="Sign In" data-fa="ورود">Sign In</button>
    </form>
  </div>
</div>
<script>
let lang=localStorage.getItem('luffy_lang')||'en';
let theme=localStorage.getItem('luffy_theme')||'dark';
function setLang(l){lang=l;document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});document.getElementById('lang-toggle').textContent=l.toUpperCase();localStorage.setItem('luffy_lang',l)}
function cycleLang(){setLang(lang==='en'?'fa':'en')}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('luffy_theme',t)}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
applyTheme(theme);setLang(lang);
document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();const err=document.getElementById('err-box');err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message;err.classList.add('show')}
});
</script>
</body>
</html>"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LUFFY PANEL | Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#050505;--surface:rgba(25,25,25,0.6);--surface2:rgba(40,40,40,0.5);--surface3:rgba(60,60,60,0.5);--border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.15);--text:rgba(255,255,255,0.95);--text2:rgba(255,255,255,0.6);--text3:rgba(255,255,255,0.3);--primary:#ef4444;--primary-glow:rgba(239,68,68,0.25);--primary-dim:rgba(239,68,68,0.15);--accent:#f59e0b;--green:#10b981;--green-dim:rgba(16,185,129,0.15);--red:#ef4444;--red-dim:rgba(239,68,68,0.15);--yellow:#f59e0b;--sidebar-bg:rgba(10,10,10,0.8);--shadow:0 8px 32px rgba(0,0,0,0.3)}
html[data-theme="light"]{--bg:#f3f4f6;--surface:rgba(255,255,255,0.7);--surface2:rgba(240,240,240,0.6);--surface3:rgba(230,230,230,0.6);--border:rgba(0,0,0,0.08);--border2:rgba(0,0,0,0.15);--text:rgba(0,0,0,0.9);--text2:rgba(0,0,0,0.6);--text3:rgba(0,0,0,0.4);--primary:#dc2626;--primary-glow:rgba(220,38,38,0.2);--primary-dim:rgba(220,38,38,0.1);--accent:#ea580c;--green:#10b981;--green-dim:rgba(16,185,129,0.1);--red:#dc2626;--red-dim:rgba(220,38,38,0.1);--yellow:#d97706;--sidebar-bg:rgba(255,255,255,0.8);--shadow:0 8px 32px rgba(0,0,0,0.05)}
html,body{height:100%}
body{font-family:'Inter','Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:background .4s,color .4s;position:relative;overflow-x:hidden}
body[dir="rtl"]{direction:rtl;text-align:right}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle at 10% 10%, var(--primary-dim), transparent 30%), radial-gradient(circle at 90% 90%, rgba(245,158,11,0.05), transparent 30%);z-index:-1;pointer-events:none}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:10px}

/* UI Elements */
.glass{backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--border);box-shadow:var(--shadow)}

.sidebar{width:240px;background:var(--sidebar-bg);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);transition:all .3s cubic-bezier(0.4, 0, 0.2, 1)}
.sidebar-brand{padding:24px 20px 20px;display:flex;align-items:center;justify-content:space-between}
.sidebar-brand-left{display:flex;align-items:center;gap:12px}
.sidebar-brand-left .brand-name{font-size:18px;font-weight:800;letter-spacing:-0.03em;background:linear-gradient(90deg, var(--primary), var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar-brand-right button{width:32px;height:32px;border-radius:10px;border:1px solid var(--border);background:var(--surface2);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.sidebar-brand-right button:hover{color:var(--primary);border-color:var(--primary)}

.sidebar-nav{flex:1;padding:12px;overflow-y:auto}
.nav-section{font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.1em;padding:16px 12px 8px}
.nav-item{display:flex;align-items:center;gap:12px;padding:12px 14px;margin:2px 0;border-radius:12px;color:var(--text2);font-size:14px;font-weight:600;cursor:pointer;transition:all .2s ease;text-decoration:none;border:none;background:transparent;width:100%;text-align:left}
.nav-item:hover{background:var(--surface2);color:var(--text);transform:translateX(4px)}
.nav-item.active{background:var(--primary-glow);color:var(--primary);border-right:3px solid var(--primary)}
.nav-icon{width:20px;height:20px;flex-shrink:0;opacity:0.8}
.nav-badge{margin-left:auto;background:var(--surface3);color:var(--text);font-size:11px;padding:2px 8px;border-radius:10px;font-weight:700}

.sidebar-footer{padding:16px;border-top:1px solid var(--border)}
.sidebar-footer .footer-row{display:flex;gap:6px;margin-bottom:10px}
.sidebar-footer .footer-btn{flex:1;padding:8px;border:1px solid var(--border);border-radius:10px;background:var(--surface2);color:var(--text2);font-size:12px;font-weight:700;cursor:pointer;transition:all .2s}
.sidebar-footer .footer-btn.active{background:var(--primary);color:#fff;border-color:var(--primary);box-shadow:0 4px 12px var(--primary-glow)}
.sidebar-footer .logout-btn{width:100%;padding:10px;border:1px solid var(--border);border-radius:10px;background:var(--red-dim);color:var(--red);font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:8px}
.sidebar-footer .logout-btn:hover{background:var(--red);color:#fff;border-color:var(--red);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

.main{margin-left:240px;flex:1;padding:32px 40px;min-height:100vh}
.page{display:none;animation:pageFade 0.4s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(10px)}
.page.active{display:block}
@keyframes pageFade{to{opacity:1;transform:translateY(0)}}

.page-header{margin-bottom:32px;display:flex;align-items:center;justify-content:space-between}
.page-title{font-size:24px;font-weight:800;color:var(--text);letter-spacing:-0.02em}
.page-sub{font-size:13px;color:var(--text3);margin-top:4px;font-weight:500}

.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin-bottom:20px}
.stat-card{background:var(--surface);border-radius:20px;padding:24px;transition:all .3s ease;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:var(--primary);opacity:0;transition:opacity .3s}
.stat-card:hover{transform:translateY(-4px);box-shadow:0 12px 30px rgba(0,0,0,0.15);border-color:var(--border2)}
.stat-card:hover::before{opacity:1}
.stat-label{font-size:12px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:12px}
.stat-value{font-size:28px;font-weight:800;color:var(--text);letter-spacing:-0.03em}
.stat-unit{font-size:14px;font-weight:500;color:var(--text2)}

.card{background:var(--surface);border-radius:20px;padding:24px;margin-bottom:20px;transition:box-shadow .3s}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.card-title{font-size:15px;font-weight:700;display:flex;align-items:center;gap:10px;color:var(--text)}

.btn{font-family:inherit;font-size:13px;font-weight:600;border-radius:10px;padding:10px 18px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;border:none;transition:all .2s ease;backdrop-filter:blur(5px)}
.btn-primary{background:linear-gradient(135deg, var(--primary), var(--accent));color:#fff;box-shadow:0 4px 12px var(--primary-glow)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 6px 16px var(--primary-glow);filter:brightness(1.1)}
.btn-secondary{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-2px)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(239,68,68,0.2)}
.btn-danger:hover{background:var(--red);color:#fff;transform:translateY(-2px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:8px}

.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px}

.table-wrap{overflow-x:auto}
.table{width:100%;border-collapse:separate;border-spacing:0}
.table th{text-align:left;font-size:12px;font-weight:700;color:var(--text3);padding:14px 16px;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid var(--border);background:var(--surface2)}
.table td{padding:14px 16px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:middle;transition:background .2s}
.table tbody tr:hover td{background:var(--surface2)}
.table tbody tr:last-child td{border-bottom:none}

.tag{display:inline-flex;align-items:center;padding:4px 10px;border-radius:8px;font-size:11px;font-weight:800;letter-spacing:0.05em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary);border:1px solid var(--primary-glow)}
.tag-active{background:var(--green-dim);color:var(--green);border:1px solid rgba(16,185,129,0.2)}
.tag-disabled{background:var(--surface3);color:var(--text3);border:1px solid var(--border)}

.usage-pill{display:flex;align-items:center;gap:12px;padding:6px 14px;border-radius:12px;background:var(--surface2);border:1px solid var(--border)}
.usage-pill .used{color:var(--text);font-weight:700;font-size:13px;min-width:55px}
.usage-pill .bar{flex:1;height:6px;background:var(--bg);border-radius:3px;min-width:80px;overflow:hidden;box-shadow:inset 0 1px 2px rgba(0,0,0,0.2)}
.usage-pill .fill{height:100%;border-radius:3px;transition:width .5s cubic-bezier(0.4,0,0.2,1)}
.usage-pill .limit{color:var(--text3);font-size:12px;font-weight:600}

.toggle{width:40px;height:22px;border-radius:12px;background:var(--surface3);position:relative;cursor:pointer;transition:all .3s ease;border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:14px;height:14px;border-radius:50%;background:var(--text3);top:3px;left:4px;transition:all .3s cubic-bezier(0.4,0,0.2,1);box-shadow:0 2px 4px rgba(0,0,0,0.2)}
.toggle.on{background:var(--green);border-color:var(--green)}
.toggle.on::after{left:20px;background:#fff}

.sys-bar{height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;box-shadow:inset 0 1px 2px rgba(0,0,0,0.2)}
.sys-bar-fill{height:100%;border-radius:4px;transition:width .5s ease}

.status-item{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid var(--border)}
.status-item:last-child{border-bottom:none}
.status-key{color:var(--text2);font-size:13px;font-weight:600}
.status-val{color:var(--text);font-weight:700;font-size:14px}

.form-group{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
.form-label{font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.05em}
.form-input,.form-select{padding:12px 14px;border-radius:10px;border:1px solid var(--border);font-family:inherit;font-size:14px;outline:none;color:var(--text);background:var(--surface2);transition:all .2s;box-shadow:inset 0 2px 4px rgba(0,0,0,0.05)}
.form-input:focus,.form-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow), inset 0 2px 4px rgba(0,0,0,0.05)}
.form-select option{background:var(--surface2);color:var(--text)}

.empty{text-align:center;padding:60px 20px;color:var(--text3)}
.empty-icon{font-size:48px;margin-bottom:16px;opacity:0.2}

.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--text);color:var(--bg);border-radius:12px;padding:12px 24px;font-size:14px;font-weight:600;opacity:0;transition:all .3s cubic-bezier(0.16,1,0.3,1);z-index:999;box-shadow:0 10px 30px rgba(0,0,0,0.3)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{background:var(--red);color:#fff}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);z-index:200;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:24px;padding:32px;width:100%;max-width:480px;position:relative;box-shadow:0 24px 60px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.1);transform:scale(0.95) translateY(10px);opacity:0;transition:all .3s cubic-bezier(0.16,1,0.3,1)}
.modal-overlay.show .modal{transform:scale(1) translateY(0);opacity:1}
.modal-title{font-size:18px;font-weight:800;margin-bottom:24px;color:var(--text)}
.modal-close{position:absolute;top:16px;left:16px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:32px;height:32px;border-radius:10px;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center;transition:all .2s}
.modal-close:hover{background:var(--red-dim);color:var(--red);border-color:rgba(239,68,68,0.3)}

.qr-box{text-align:center;padding:24px;background:var(--surface2);border-radius:16px;margin-top:16px;border:1px solid var(--border);box-shadow:inset 0 2px 10px rgba(0,0,0,0.1)}
.qr-box img{max-width:240px;border-radius:12px;border:4px solid var(--surface);box-shadow:0 8px 24px rgba(0,0,0,0.2)}

.btn-icon{width:32px;height:32px;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;border:none;cursor:pointer;transition:all .2s;font-size:14px;color:var(--text2);background:var(--surface3)}
.btn-icon:hover{background:var(--primary);color:#fff;transform:translateY(-2px);box-shadow:0 4px 12px var(--primary-glow)}

.inbounds-toolbar{display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.search-box{flex:1;min-width:200px;position:relative}
.search-box input{width:100%;padding:12px 16px 12px 40px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;color:var(--text);font-size:13px;font-family:inherit;outline:none;transition:all .2s}
.search-box input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.search-box svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--text3)}
.filter-chips{display:flex;gap:4px;padding:4px;background:var(--surface2);border:1px solid var(--border);border-radius:12px}
.chip{padding:8px 16px;border-radius:8px;font-size:12px;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:transparent;transition:all .2s;font-family:inherit}
.chip.active{background:var(--primary);color:#fff;box-shadow:0 2px 8px var(--primary-glow)}
.chip:hover:not(.active){color:var(--text)}

.mobile-header{display:none;position:fixed;top:0;left:0;right:0;height:56px;background:var(--sidebar-bg);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 20px}
.menu-toggle{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:var(--surface2);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:18px}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:99}
.sidebar-overlay.show{display:block}
.inbound-cards{display:none}

@media(max-width:900px){
  .sidebar{transform:translateX(-100%);z-index:200}
  .sidebar.open{transform:translateX(0);box-shadow:10px 0 30px rgba(0,0,0,0.5)}
  .main{margin-left:0;padding:80px 20px 40px}
  .mobile-header{display:flex}
  .stats-row{grid-template-columns:1fr 1fr}
  .grid-2{grid-template-columns:1fr}
}
@media(max-width:600px){
  .stats-row{grid-template-columns:1fr}
  .table-wrap{display:none}
  .inbound-cards{display:flex;flex-direction:column;gap:12px}
  .inbound-card{background:var(--surface2);border:1px solid var(--border);border-radius:16px;padding:16px}
  .inbounds-toolbar{flex-direction:column;align-items:stretch}
}
</style>
</head>
<body class="glass">

<div class="toast" id="toast"></div>

<div class="mobile-header">
  <span style="font-weight:800;font-size:16px;background:linear-gradient(90deg, var(--primary), var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent">LUFFY</span>
  <button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-overlay').classList.toggle('show')">&#9776;</button>
</div>
<div class="sidebar-overlay" id="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('show')"></div>

<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-brand-left">
      <svg width="32" height="32" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="14" fill="url(#lg)"/>
        <path d="M18 14h6v22h14v6H18V14z" fill="#fff" opacity="0.95"/>
        <defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#ef4444"/><stop offset="1" stop-color="#f59e0b"/></linearGradient></defs>
      </svg>
      <span class="brand-name">LUFFY</span>
    </div>
    <div class="sidebar-brand-right">
      <button onclick="toggleTheme()" id="theme-btn" title="Toggle theme">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      </button>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" data-page="dashboard">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></svg>
      <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
    </button>
    <button class="nav-item" data-page="inbounds">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
      <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
      <span class="nav-badge" id="links-badge">0</span>
    </button>
    <button class="nav-item" data-page="traffic">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      <span data-en="Traffic" data-fa="ترافیک">Traffic</span>
    </button>
    <div class="nav-section">System</div>
    <button class="nav-item" data-page="settings">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
      <span data-en="Settings" data-fa="تنظیمات">Settings</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    <div class="footer-row">
      <button class="footer-btn active" onclick="setLang('en')" id="lang-en">EN</button>
      <button class="footer-btn" onclick="setLang('fa')" id="lang-fa">FA</button>
    </div>
    <button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Logout" data-fa="خروج">Logout</span>
    </button>
    <div class="version" style="text-align:center;font-size:11px;color:var(--text3);margin-top:10px">v3.5 Glass Edition</div>
  </div>
</aside>

<main class="main">
  <section class="page active" id="page-dashboard">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
        <div class="page-sub" id="last-update">Updated: --</div>
      </div>
      <div style="display:flex;gap:10px">
        <button class="btn btn-secondary" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat-card glass">
        <div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div>
        <div class="stat-value" id="s-traffic">--<span class="stat-unit"> MB</span></div>
      </div>
      <div class="stat-card glass">
        <div class="stat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="stat-value" id="s-links">--</div>
      </div>
      <div class="stat-card glass">
        <div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div>
        <div class="stat-value" id="s-uptime" style="font-size:22px">--</div>
      </div>
      <div class="stat-card glass">
        <div class="stat-label" data-en="Domain" data-fa="دامنه">Domain / IP</div>
        <div class="stat-value" id="s-domain" style="font-size:14px;word-break:break-all;font-weight:600">--</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card glass">
        <div class="card-header"><div class="card-title">CPU Usage</div><span id="s-cpu-val" style="font-size:20px;font-weight:800;color:var(--primary)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-cpu-bar" style="width:0%;background:var(--primary)"></div></div>
      </div>
      <div class="card glass">
        <div class="card-header"><div class="card-title">Memory</div><span id="s-mem-val" style="font-size:20px;font-weight:800;color:var(--green)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-mem-bar" style="width:0%;background:var(--green)"></div></div>
      </div>
    </div>
    <div class="card glass">
      <div class="card-header"><div class="card-title">Traffic Chart</div></div>
      <div style="height:200px"><canvas id="trafficChart"></canvas></div>
    </div>
  </section>

  <section class="page" id="page-inbounds">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="page-sub">VLESS over WebSocket</div>
      </div>
      <button class="btn btn-primary" onclick="showAddModal()">+ Add Inbound</button>
    </div>
    <div class="inbounds-toolbar">
      <div class="search-box">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="inbound-search" placeholder="Search by name or UUID..." oninput="filterInbounds()">
      </div>
      <div class="filter-chips">
        <button class="chip active" onclick="setFilter('all',this)">All</button>
        <button class="chip" onclick="setFilter('active',this)">Active</button>
        <button class="chip" onclick="setFilter('disabled',this)">Disabled</button>
      </div>
    </div>
    <div class="card glass" style="padding:0;overflow:hidden">
      <div class="table-wrap">
        <table class="table">
          <thead><tr>
            <th style="width:40px;text-align:center">#</th>
            <th>Remark</th>
            <th style="width:80px">Type</th>
            <th>Traffic Usage</th>
            <th style="width:80px">Status</th>
            <th style="width:180px;text-align:right">Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="inbound-cards" id="inbound-cards" style="padding:16px"></div>
      <div class="empty" id="links-empty" style="display:none">
        <div class="empty-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg></div>
        <div>No inbounds found</div>
      </div>
    </div>
  </section>

  <section class="page" id="page-traffic">
    <div class="page-header"><div><div class="page-title">Traffic Details</div></div></div>
    <div class="card glass">
      <div class="card-header"><div class="card-title">Global Stats</div></div>
      <div class="status-item"><span class="status-key">Total Traffic Sent/Received</span><span class="status-val" id="t-traffic">-- MB</span></div>
      <div class="status-item"><span class="status-key">Total WebSocket Requests</span><span class="status-val" id="t-reqs">--</span></div>
      <div class="status-item"><span class="status-key">Server Uptime</span><span class="status-val" id="t-uptime">--</span></div>
    </div>
  </section>

  <section class="page" id="page-settings">
    <div class="page-header"><div><div class="page-title" data-en="Settings" data-fa="تنظیمات">System Settings</div></div></div>
    
    <div class="grid-2">
      <div class="card glass">
        <div class="card-header"><div class="card-title">Network / Clean IP</div></div>
        <div class="form-group">
          <label class="form-label">Clean IP or Custom Domain</label>
          <input class="form-input" type="text" id="setting-clean-ip" placeholder="e.g. 104.21.22.22 or zula.ir">
          <div style="font-size:11px;color:var(--text3);margin-top:6px;line-height:1.4">
            If provided, this IP/Domain will be used as the main Address in all your VLESS links. 
            Leave empty to use the default server domain.
          </div>
        </div>
        <button class="btn btn-primary" onclick="updateNetworkSettings()" style="margin-top:8px;width:100%">Save Network Settings</button>
      </div>

      <div class="card glass">
        <div class="card-header"><div class="card-title">Security Settings</div></div>
        <div class="form-group">
          <label class="form-label">Current Password</label>
          <input class="form-input" type="password" id="cur-pw" placeholder="Enter current password">
        </div>
        <div class="form-group">
          <label class="form-label">New Password</label>
          <input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters">
        </div>
        <button class="btn btn-secondary" onclick="changePassword()" style="margin-top:8px;width:100%">Update Password</button>
      </div>
    </div>
  </section>
</main>

<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#add-modal').classList.remove('show')">✕</button>
    <div class="modal-title">Create New Inbound</div>
    <div class="form-group">
      <label class="form-label">Remark (Name)</label>
      <input class="form-input" id="new-label" placeholder="e.g. VIP User">
    </div>
    <div style="display:flex;gap:12px">
      <div class="form-group" style="flex:1">
        <label class="form-label">Traffic Limit</label>
        <input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="form-group" style="width:100px">
        <label class="form-label">Unit</label>
        <select class="form-select" id="new-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;margin-top:16px">Create Inbound</button>
  </div>
</div>

<div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="max-width:540px">
    <button class="modal-close" onclick="$('#detail-modal').classList.remove('show')">✕</button>
    <div class="modal-title" id="detail-title">Details</div>
    <div id="detail-content"></div>
  </div>
</div>

<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="max-width:360px;text-align:center">
    <button class="modal-close" onclick="$('#qr-modal').classList.remove('show')">✕</button>
    <div class="modal-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <button class="btn btn-primary" onclick="downloadQR()" style="margin-top:20px;width:100%">Download QR Image</button>
  </div>
</div>

<script>
let lang=localStorage.getItem('luffy_lang')||'en';
let theme=localStorage.getItem('luffy_theme')||'dark';
let allLinks=[];let currentFilter='all';let statsData={};let trafficChart=null;

function setLang(l){lang=l;document.getElementById('lang-en').classList.toggle('active',l==='en');document.getElementById('lang-fa').classList.toggle('active',l==='fa');document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});localStorage.setItem('luffy_lang',l)}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('luffy_theme',t);const btn=$('#theme-btn');if(btn)btn.innerHTML=t==='dark'?'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>':'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>'}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
function showAddModal(){$('#add-modal').classList.add('show')}
function setFilter(f,el){currentFilter=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterInbounds()}
function filterInbounds(){const q=($('#inbound-search')?.value||'').toLowerCase();let filtered=allLinks;if(currentFilter==='active')filtered=filtered.filter(l=>l.active);if(currentFilter==='disabled')filtered=filtered.filter(l=>!l.active);if(q)filtered=filtered.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(filtered)}
function fmtBytes(b){return b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB'}
function fmtLimit(b){if(b===0)return'∞';const gb=b/1073741824;return(gb%1===0?gb.toFixed(0):gb.toFixed(1))+' GB'}

const $=s=>document.querySelector(s);
const $$=s=>document.querySelectorAll(s);
$$('.nav-item').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
function switchPage(id){$$('.page').forEach(p=>p.classList.remove('active'));$(`#page-${id}`)?.classList.add('active');$$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));$('#sidebar').classList.remove('open');$('#sidebar-overlay').classList.remove('show')}
function toast(msg,err=false){const t=$('#toast');t.textContent=msg;t.className='toast'+(err?' error':'')+' show';setTimeout(()=>t.classList.remove('show'),3000)}
function esc(s){return s.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

// Icons SVG definitions
const icInfo = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
const icCopy = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`;
const icQR = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`;
const icTrash = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>`;

async function loadSettings(){
  try{
    const r=await fetch('/api/settings');
    if(r.ok){
      const data=await r.json();
      $('#setting-clean-ip').value=data.clean_ip||'';
    }
  }catch(e){}
}

async function updateNetworkSettings(){
  const clean_ip=$('#setting-clean-ip').value.trim();
  try{
    const r=await fetch('/api/settings',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({clean_ip})});
    if(!r.ok)throw new Error();
    toast('Network Settings Saved');
    await loadLinks(); // دریافت دوباره لینک‌ها برای بروز شدن IP ها در جدول
  }catch(e){
    toast('Failed to save settings',true);
  }
}

async function loadStats(){
  try{
    const r=await fetch('/stats');if(!r.ok)throw new Error();statsData=await r.json();
    $('#s-traffic').innerHTML=statsData.total_traffic_mb+'<span class="stat-unit"> MB</span>';
    $('#s-links').textContent=statsData.links_count;
    $('#s-uptime').textContent=statsData.uptime;
    $('#s-domain').textContent=statsData.domain;
    $('#links-badge').textContent=statsData.links_count;
    $('#last-update').textContent=(lang==='fa'?'Last update: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
    if($('#t-traffic'))$('#t-traffic').textContent=statsData.total_traffic_mb+' MB';
    if($('#t-reqs'))$('#t-reqs').textContent=statsData.total_requests.toLocaleString();
    if($('#t-uptime'))$('#t-uptime').textContent=statsData.uptime;
    if(statsData.cpu_percent!==undefined){const c=statsData.cpu_percent;const cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--primary)';$('#s-cpu-val').textContent=c.toFixed(1)+'%';$('#s-cpu-val').style.color=cc;$('#s-cpu-bar').style.width=c+'%';$('#s-cpu-bar').style.background=cc}
    if(statsData.memory_percent!==undefined){const m=statsData.memory_percent;const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';$('#s-mem-val').textContent=m.toFixed(1)+'%';$('#s-mem-val').style.color=mc;$('#s-mem-bar').style.width=m+'%';$('#s-mem-bar').style.background=mc}
    updateChart();
  }catch(e){}
}

async function loadLinks(){try{const r=await fetch('/api/links');if(!r.ok)throw new Error();const d=await r.json();allLinks=d.links||[];filterInbounds();}catch(e){}}

function renderLinks(links){
  const tbody=$('#links-tbody');const empty=$('#links-empty');const cards=$('#inbound-cards');
  if(!links.length){tbody.innerHTML='';cards.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes,lim=l.limit_bytes;
    const uF=fmtBytes(u);const lF=fmtLimit(lim);
    const pct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const i=idx--;
    return {l,uF,lF,pct,col,i};
  });
  
  tbody.innerHTML=rows.map(r=>`<tr>
    <td style="text-align:center;color:var(--text3);font-weight:700">${r.i}</td>
    <td style="font-weight:700;color:var(--text)">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">VLESS</span></td>
    <td><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div></td>
    <td><span class="tag ${r.l.active?'tag-active':'tag-disabled'}">${r.l.active?'Active':'Disabled'}</span></td>
    <td style="text-align:right"><div style="display:inline-flex;gap:6px;align-items:center">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)" style="margin-right:10px"></button>
      <button class="btn-icon" onclick="showDetail('${r.l.uuid}')" title="Info">${icInfo}</button>
      <button class="btn-icon" onclick="copyLinkText('${esc(r.l.vless_link)}')" title="Copy">${icCopy}</button>
      <button class="btn-icon" onclick="showQRText('${esc(r.l.vless_link)}')" title="QR">${icQR}</button>
      <button class="btn-icon" onclick="deleteLink('${r.l.uuid}')" title="Delete" style="color:var(--red);background:var(--red-dim)">${icTrash}</button>
    </div></td>
  </tr>`).join('');

  cards.innerHTML=rows.map(r=>`<div class="inbound-card glass">
    <div style="display:flex;justify-content:space-between;margin-bottom:12px">
      <div style="font-weight:700;font-size:15px">${esc(r.l.label)} <span style="font-size:11px;color:var(--text3)">#${r.i}</span></div>
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
    </div>
    <div class="usage-pill" style="margin-bottom:16px"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn-icon" onclick="showDetail('${r.l.uuid}')">${icInfo}</button>
      <button class="btn-icon" onclick="copyLinkText('${esc(r.l.vless_link)}')">${icCopy}</button>
      <button class="btn-icon" onclick="showQRText('${esc(r.l.vless_link)}')">${icQR}</button>
      <button class="btn-icon" onclick="deleteLink('${r.l.uuid}')" style="color:var(--red);background:var(--red-dim)">${icTrash}</button>
    </div>
  </div>`).join('');
}

async function toggleLink(el){
  const uid=el.dataset.uid;
  const link=allLinks.find(l=>l.uuid===uid);
  if(!link)return;
  const newActive=!link.active;
  try{
    await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newActive})});
    link.active=newActive;
    filterInbounds();
    loadStats();
  }catch(e){}
}

async function quickCreate(limit,unit){
  const names=['Alpha','Beta','Gamma','Delta','Omega','Neon','Nova','Apex','Zenith','Nexus'];
  const name=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*100);
  try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:name,limit_value:limit,limit_unit:unit})});if(!r.ok)throw new Error();toast('Created: '+name);await loadLinks();await loadStats();}catch(e){toast('Error',true)}
}

async function createLink(){
  const label=$('#new-label').value.trim()||'New Inbound';const val=parseFloat($('#new-limit').value)||0;const unit=$('#new-unit').value||'GB';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English letters allowed',true);return;}
  try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:val,limit_unit:unit})});if(!r.ok)throw new Error();toast('Inbound Created');$('#new-label').value='';$('#new-limit').value='';$('#add-modal').classList.remove('show');await loadLinks();await loadStats();}catch(e){toast('Error',true)}
}

async function resetUsage(uid){try{await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Traffic Reset');await loadLinks();}catch(e){}}
async function deleteLink(uid){if(!confirm('Permanently delete this inbound?'))return;try{await fetch(`/api/links/${uid}`,{method:'DELETE'});toast('Deleted');await loadLinks();await loadStats();}catch(e){}}

function showDetail(uid){
  const l=allLinks.find(x=>x.uuid===uid);if(!l)return;
  const u=l.used_bytes,lim=l.limit_bytes;const uF=fmtBytes(u);const lF=fmtLimit(lim);
  const pct=lim>0?Math.min(100,(u/lim)*100):0;const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
  const created=l.created_at?new Date(l.created_at).toLocaleString(lang==='fa'?'fa-IR':'en-US'):'--';
  $('#detail-title').textContent=l.label;
  $('#detail-content').innerHTML=`
    <div style="display:flex;gap:20px;margin-bottom:24px">
      <div style="flex:1;background:var(--surface2);padding:12px;border-radius:12px;border:1px solid var(--border)">
        <div style="font-size:11px;color:var(--text3);text-transform:uppercase;font-weight:700;margin-bottom:4px">Protocol</div>
        <div style="font-weight:800;color:var(--primary)">VLESS</div>
      </div>
      <div style="flex:1;background:var(--surface2);padding:12px;border-radius:12px;border:1px solid var(--border)">
        <div style="font-size:11px;color:var(--text3);text-transform:uppercase;font-weight:700;margin-bottom:4px">Status</div>
        <div style="font-weight:800;color:${l.active?'var(--green)':'var(--red)'}">${l.active?'Active':'Disabled'}</div>
      </div>
    </div>
    
    <div class="form-group">
      <label class="form-label">Traffic Usage (${pct.toFixed(1)}%)</label>
      <div class="usage-pill" style="margin-top:4px"><span class="used">${uF}</span><div class="bar"><div class="fill" style="width:${pct}%;background:${col}"></div></div><span class="limit">${lF}</span></div>
    </div>
    
    <div class="form-group" style="margin-top:20px">
      <label class="form-label">Config Link</label>
      <div style="padding:12px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;font-family:monospace;font-size:12px;word-break:break-all;color:var(--text2);line-height:1.5">${esc(l.vless_link)}</div>
    </div>
    
    <div style="display:flex;gap:10px;margin-top:24px">
      <button class="btn btn-primary" onclick="copyLinkText('${esc(l.vless_link)}');$('#detail-modal').classList.remove('show')" style="flex:1">Copy Link</button>
      <button class="btn btn-secondary" onclick="resetUsage('${l.uuid}');$('#detail-modal').classList.remove('show')" style="flex:1">Reset Traffic</button>
    </div>`;
  $('#detail-modal').classList.add('show');
}

function copyLinkText(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied to clipboard')).catch(()=>toast('Failed to copy',true))}
function showQRText(txt){if(!txt)return;$('#qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=300x300&margin=1&color=050505&bgcolor=ffffff&data='+encodeURIComponent(txt);$('#qr-modal').classList.add('show');}
function downloadQR(){const img=$('#qr-img');if(!img.src)return;const a=document.createElement('a');a.href=img.src;a.download='luffy-qr.png';a.click()}

async function changePassword(){
  const cur=$('#cur-pw').value;const nw=$('#new-pw').value;
  if(!cur||!nw){toast('Fill all fields',true);return;}
  try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}toast('Password Updated');$('#cur-pw').value='';$('#new-pw').value='';}catch(e){toast(e.message,true)}
}

applyTheme(theme);setLang(lang);
loadSettings(); // بارگیری تنظیمات
loadStats();loadLinks();
setInterval(()=>{loadStats()},10000);

let chartLabels=[];let chartData=[];
function initChart(){
  const ctx=document.getElementById('trafficChart');if(!ctx)return;
  trafficChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'Traffic (MB)',data:[],backgroundColor:'rgba(239,68,68,0.2)',borderColor:'#ef4444',borderWidth:3,tension:0.4,fill:true,pointBackgroundColor:'#ef4444',pointBorderColor:'#fff',pointRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(255,255,255,0.4)',font:{size:11,family:'Inter'}}},y:{grid:{color:'rgba(255,255,255,0.05)',borderDash:[5,5]},ticks:{color:'rgba(255,255,255,0.4)',font:{size:11,family:'Inter'},callback:v=>v+' MB'},beginAtZero:true}}}});
}
initChart();
function updateChart(){
  if(!trafficChart||!statsData.hourly_traffic)return;
  const ht=statsData.hourly_traffic;
  const sorted=Object.entries(ht).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);
  const labels=sorted.map(e=>e[0]);
  const data=sorted.map(e=>Math.round(e[1]/1048576));
  trafficChart.data.labels=labels;trafficChart.data.datasets[0].data=data;
  trafficChart.update();
}
</script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
