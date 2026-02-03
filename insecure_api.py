from fastapi import FastAPI, Header, HTTPException, Body
import sqlite3
import jwt
import time
import hashlib
import random
import logging
import subprocess
import requests

# Extras para disparar más hallazgos en análisis estático
import os
import pickle
import tempfile
import base64
import re

# Opcional: puede no estar instalado, igual sirve para análisis estático
try:
    import yaml
except Exception:
    yaml = None
#comentario
app = FastAPI(title="Insecure Demo API (Sonar Alerts)")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("insecure-api")

DB_PATH = "insecure_demo.db"

# ✅ Sonar suele marcar esto como secreto/credencial hardcodeada
JWT_SECRET = "super-secret"
JWT_ALG = "HS256"

# ✅ Hardcoded credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# ✅ Hardcoded "cloud keys" (DUMMY, para que Sonar lo marque)
AWS_ACCESS_KEY_ID = "AKIA1234567890EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        full_name TEXT,
        role TEXT
    )
    """
    )
    conn.commit()

    # seed
    try:
        cur.execute(
            "INSERT INTO users(username,password,full_name,role) VALUES (?,?,?,?)",
            (ADMIN_USERNAME, ADMIN_PASSWORD, "Admin User", "admin"),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


init_db()


def issue_token(username: str, uid: int, role: str) -> str:
    payload = {
        "sub": username,
        "uid": uid,
        "role": role,
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(auth: str | None):
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing/invalid Authorization header")
    token = auth.split(" ", 1)[1].strip()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------------------------------------------------------
# 1) LOGIN (con alertas intencionales)
# -------------------------------------------------------
@app.post("/login")
def login(username: str, password: str):
    # ✅ Sonar: exposición de datos sensibles en logs
    logger.info("Login attempt user=%s password=%s", username, password)

    conn = db()
    cur = conn.cursor()

    # ✅ SQLi (inseguro; Sonar puede marcar)
    q = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    row = cur.execute(q).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Bad credentials")

    return {"access_token": issue_token(row["username"], row["id"], row["role"]), "token_type": "bearer"}


# -------------------------------------------------------
# 2) Hash débil (MD5) - alerta típica
# -------------------------------------------------------
@app.get("/debug/hash")
def debug_weak_hash(value: str):
    # ✅ Sonar: weak hashing algorithm (MD5)
    digest = hashlib.md5(value.encode("utf-8")).hexdigest()
    return {"value": value, "md5": digest}


# -------------------------------------------------------
# 3) Eval() - alerta típica
# -------------------------------------------------------
@app.post("/debug/eval")
def debug_eval(expression: str):
    # ✅ Sonar: use of eval is dangerous
    result = eval(expression)  # nosec (intencional)
    return {"expression": expression, "result": result}


# -------------------------------------------------------
# 4) Command execution con shell=True - alerta típica
# -------------------------------------------------------
@app.post("/debug/ping")
def debug_ping(host: str, authorization: str | None = Header(default=None)):
    _claims = decode_token(authorization)

    # ✅ Sonar: command injection risk (shell=True + input)
    cmd = f"ping -c 1 {host}"
    completed = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # nosec (intencional)

    return {
        "cmd": cmd,
        "returncode": completed.returncode,
        "stdout": completed.stdout[:5000],
        "stderr": completed.stderr[:5000],
    }


# -------------------------------------------------------
# 5) TLS verify=False - alerta típica
# -------------------------------------------------------
@app.get("/debug/fetch")
def debug_fetch(url: str):
    # ✅ Sonar: certificate verification disabled
    r = requests.get(url, timeout=5, verify=False)  # nosec (intencional)
    return {"url": url, "status_code": r.status_code, "body_preview": r.text[:500]}


# -------------------------------------------------------
# 6) Random inseguro para token - alerta típica
# -------------------------------------------------------
@app.get("/debug/insecure-token")
def debug_insecure_token():
    # ✅ Sonar: use of insecure random for security purposes
    token = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(24))
    return {"token": token}


# -------------------------------------------------------
# 7) Endpoint protegido simple para pruebas
# -------------------------------------------------------
@app.get("/me")
def me(authorization: str | None = Header(default=None)):
    claims = decode_token(authorization)
    return {"claims": claims}


# -------------------------------------------------------
# 8) Deserialización insegura (pickle) - alerta típica
# -------------------------------------------------------
@app.post("/debug/pickle")
def debug_pickle(payload_b64: str = Body(..., embed=True)):
    # ✅ Sonar: insecure deserialization
    data = base64.b64decode(payload_b64)
    obj = pickle.loads(data)  # nosec (intencional)
    return {"type": str(type(obj)), "repr": str(obj)[:200]}


# -------------------------------------------------------
# 9) Path Traversal / lectura arbitraria - alerta típica
# -------------------------------------------------------
@app.get("/debug/readfile")
def debug_readfile(path: str):
    # ✅ Sonar: untrusted path / path traversal
    with open(path, "r", encoding="utf-8", errors="ignore") as f:  # nosec (intencional)
        return {"path": path, "preview": f.read(500)}


# -------------------------------------------------------
# 10) os.system() - ejecución de comandos peligrosa
# -------------------------------------------------------
@app.get("/debug/os-system")
def debug_os_system():
    # ✅ Sonar: os.system is dangerous
    cmd = os.environ.get("CMD", "id")
    rc = os.system(cmd)  # nosec (intencional)
    return {"cmd": cmd, "returncode": rc}


# -------------------------------------------------------
# 11) Archivo temporal inseguro (mktemp) - alerta típica
# -------------------------------------------------------
@app.post("/debug/tempfile")
def debug_tempfile(content: str = Body(..., embed=True)):
    # ✅ Sonar: insecure temporary file (mktemp)
    name = tempfile.mktemp(prefix="demo-")  # nosec (intencional)
    with open(name, "w", encoding="utf-8") as f:
        f.write(content)
    return {"temp_file": name}


# -------------------------------------------------------
# 12) YAML load inseguro (si PyYAML está instalado) - alerta típica
# -------------------------------------------------------
@app.post("/debug/yaml")
def debug_yaml(yaml_text: str = Body(..., embed=True)):
    # ✅ Sonar: yaml.load can be unsafe (use safe_load)
    if yaml is None:
        return {"error": "PyYAML not installed, endpoint included for static analysis demo"}
    obj = yaml.load(yaml_text, Loader=yaml.FullLoader)  # nosec (intencional)
    return {"type": str(type(obj)), "repr": str(obj)[:200]}


# -------------------------------------------------------
# 13) Regex vulnerable a ReDoS - alerta típica
# -------------------------------------------------------
@app.get("/debug/regex")
def debug_regex(user_input: str):
    # ✅ Sonar: potentially catastrophic backtracking (ReDoS)
    pattern = r"^(a+)+$"
    matched = re.match(pattern, user_input) is not None
    return {"pattern": pattern, "input_len": len(user_input), "matched": matched}


# -------------------------------------------------------
# 14) Comparación insegura de secretos (timing attack) - alerta típica
# -------------------------------------------------------
@app.get("/debug/compare")
def debug_compare(secret: str):
    # ✅ Sonar: non-constant time comparison for secrets
    if secret == JWT_SECRET:
        return {"ok": True}
    return {"ok": False}


# -------------------------------------------------------
# 15) Ejemplo de envío de credenciales por HTTP (sin TLS) - alerta típica
# -------------------------------------------------------
@app.post("/debug/http-basic")
def debug_http_basic(username: str = Body(...), password: str = Body(...)):
    # ✅ Sonar: hardcoded http / insecure transport (depende del profile, pero útil)
    # Solo demostración: NO usar en real.
    url = "http://example.com/login"
    # En la práctica, esto expondría credenciales si alguien intercepta.
    return {"warning": "Demo only", "url": url, "username": username, "password_len": len(password)}
