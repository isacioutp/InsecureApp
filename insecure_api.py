# Ejecutar: uvicorn insecure_api:app --reload
from fastapi import FastAPI, Header, HTTPException
import sqlite3
import jwt
import time

app = FastAPI(title="Insecure Demo API")

JWT_SECRET = "super-secret"
JWT_ALG = "HS256"

DB_PATH = "insecure_demo.db"

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        full_name TEXT,
        role TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT
    )
    """)
    conn.commit()

    # Seed básico (si no existen)
    try:
        cur.execute("INSERT INTO users(username,password,full_name,role) VALUES ('admin','admin123','Admin User','admin')")
        cur.execute("INSERT INTO users(username,password,full_name,role) VALUES ('alice','alice123','Alice Doe','user')")
        cur.execute("INSERT INTO notes(user_id,content) VALUES (1,'Nota secreta del admin')")
        cur.execute("INSERT INTO notes(user_id,content) VALUES (2,'Nota privada de Alice')")
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

init_db()


def issue_token(user: sqlite3.Row) -> str:
    payload = {
        "sub": user["username"],
        "uid": user["id"],
        "role": user["role"],
        "exp": int(time.time()) + 3600
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


# ---------------------------
# AUTH
# ---------------------------
@app.post("/login")
def login(username: str, password: str):
    conn = db()
    cur = conn.cursor()

    # ❌ SQLi: concatenación directa (NO parametrizado)
    q = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    row = cur.execute(q).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Bad credentials")

    return {"access_token": issue_token(row), "token_type": "bearer"}


# =========================================================
# USERS CRUD (INSEGURO)
# =========================================================

@app.get("/users")
def list_users(authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ expone info (incluye password)
    rows = cur.execute("SELECT * FROM users").fetchall()
    conn.close()
    return {"count": len(rows), "items": [dict(r) for r in rows]}


@app.get("/users/{user_id}")
def get_user(user_id: int, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ IDOR: cualquiera autenticado puede pedir cualquier user_id
    row = cur.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)


@app.post("/users")
def create_user(username: str, password: str, authorization: str, full_name: str = "", role: str = "user" ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ sin validación, password en texto plano, SQLi por concatenación
    cur.execute(
        f"INSERT INTO users(username,password,full_name,role) VALUES ('{username}','{password}','{full_name}','{role}')"
    )
    conn.commit()
    new_id = cur.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return {"ok": True, "id": new_id}


@app.put("/users/{user_id}")
def update_user(user_id: int, username: str, password: str, full_name: str, role: str,
                authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ cualquiera puede editar cualquier usuario (IDOR) + SQLi
    cur.execute(
        f"UPDATE users SET username='{username}', password='{password}', full_name='{full_name}', role='{role}' "
        f"WHERE id={user_id}"
    )
    conn.commit()
    conn.close()
    return {"ok": True, "message": "User updated"}


@app.patch("/users/{user_id}")
def patch_user(user_id: int, authorization: str, username: str | None = None, password: str | None = None,
               full_name: str | None = None, role: str | None = None ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ construcción de SQL dinámica, vulnerable
    updates = []
    if username is not None:
        updates.append(f"username='{username}'")
    if password is not None:
        updates.append(f"password='{password}'")
    if full_name is not None:
        updates.append(f"full_name='{full_name}'")
    if role is not None:
        updates.append(f"role='{role}'")

    if not updates:
        conn.close()
        return {"ok": True, "message": "Nothing to update"}

    q = f"UPDATE users SET {', '.join(updates)} WHERE id={user_id}"
    cur.execute(q)
    conn.commit()
    conn.close()
    return {"ok": True, "message": "User patched"}


@app.delete("/users/{user_id}")
def delete_user(user_id: int, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ cualquiera puede borrar cualquier usuario (IDOR)
    cur.execute(f"DELETE FROM users WHERE id={user_id}")
    conn.commit()
    conn.close()
    return {"ok": True, "message": "User deleted"}


@app.get("/users/search")
def search_users(q: str, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ SQLi en búsqueda
    rows = cur.execute(f"SELECT * FROM users WHERE username LIKE '{q}' OR full_name LIKE '{q}'").fetchall()
    conn.close()
    return {"count": len(rows), "items": [dict(r) for r in rows]}


# =========================================================
# NOTES CRUD (INSEGURO)
# =========================================================

@app.get("/notes")
def list_notes(authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ expone todas las notas, sin filtrar por usuario
    rows = cur.execute("SELECT * FROM notes").fetchall()
    conn.close()
    return {"count": len(rows), "items": [dict(r) for r in rows]}


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ IDOR: cualquiera puede leer cualquier nota por id
    row = cur.execute(f"SELECT * FROM notes WHERE id={note_id}").fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(user_id: int, content: str, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ permite suplantación: user_id arbitrario + SQLi (content)
    cur.execute(f"INSERT INTO notes(user_id, content) VALUES ({user_id}, '{content}')")
    conn.commit()
    new_id = cur.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return {"ok": True, "id": new_id}


@app.put("/notes/{note_id}")
def update_note(note_id: int, user_id: int, content: str, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ cualquiera puede modificar cualquier nota + puede cambiarle el dueño
    cur.execute(f"UPDATE notes SET user_id={user_id}, content='{content}' WHERE id={note_id}")
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Note updated"}


@app.patch("/notes/{note_id}")
def patch_note(note_id: int, authorization: str, user_id: int | None = None, content: str | None = None ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ SQL dinámica vulnerable
    updates = []
    if user_id is not None:
        updates.append(f"user_id={user_id}")
    if content is not None:
        updates.append(f"content='{content}'")

    if not updates:
        conn.close()
        return {"ok": True, "message": "Nothing to update"}

    cur.execute(f"UPDATE notes SET {', '.join(updates)} WHERE id={note_id}")
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Note patched"}


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ cualquiera puede borrar cualquier nota
    cur.execute(f"DELETE FROM notes WHERE id={note_id}")
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Note deleted"}


@app.get("/notes/by-user/{user_id}")
def notes_by_user(user_id: int, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ IDOR: puedes listar notas de cualquier user_id
    rows = cur.execute(f"SELECT * FROM notes WHERE user_id={user_id}").fetchall()
    conn.close()
    return {"count": len(rows), "items": [dict(r) for r in rows]}


@app.get("/notes/search")
def search_notes(q: str, authorization: str ):
    _claims = decode_token(authorization)
    conn = db()
    cur = conn.cursor()

    # ❌ SQLi: q se pega directo
    rows = cur.execute(f"SELECT * FROM notes WHERE content LIKE '{q}'").fetchall()
    conn.close()
    return {"count": len(rows), "items": [dict(r) for r in rows]}