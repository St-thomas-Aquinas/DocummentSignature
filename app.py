import os
import sqlite3
import json
import requests
from flask import Flask, request, jsonify

# ==============================
# ENV VARIABLES (RENDER SAFE)
# ==============================

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GIST_ID = os.environ.get("GIST_ID")

if not GITHUB_TOKEN:
    print("WARNING: Missing GITHUB_TOKEN")

if not GIST_ID:
    print("WARNING: Missing GIST_ID")

# ==============================
# FLASK APP (IMPORTANT FIX)
# ==============================

app = Flask(__name__)   # 🔥 THIS MUST EXIST FOR GUNICORN

# ==============================
# DATABASE
# ==============================

DB = "users.db"

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        encrypted_private_key TEXT
    )
    """)

    conn.commit()
    conn.close()

# ==============================
# EXPORT DB
# ==============================

def export_db():

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
        SELECT username, password_hash, public_key, encrypted_private_key
        FROM users
    """)

    rows = cur.fetchall()
    conn.close()

    users = []

    for r in rows:
        users.append({
            "username": r[0],
            "password_hash": r[1],
            "public_key": r[2],
            "encrypted_private_key": r[3]
        })

    return json.dumps(users, indent=2)

# ==============================
# BACKUP TO GIST
# ==============================

def backup_to_gist():

    if not GITHUB_TOKEN or not GIST_ID:
        print("Backup skipped (missing env vars)")
        return

    url = f"https://api.github.com/gists/{GIST_ID}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}"
    }

    payload = {
        "files": {
            "backup.json": {
                "content": export_db()
            }
        }
    }

    r = requests.patch(url, headers=headers, json=payload)

    if r.status_code == 200:
        print("Backup success")
    else:
        print("Backup failed:", r.text)

# ==============================
# RESTORE FROM GIST
# ==============================

def restore_from_gist():

    if not GITHUB_TOKEN or not GIST_ID:
        print("Restore skipped (missing env vars)")
        return

    url = f"https://api.github.com/gists/{GIST_ID}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}"
    }

    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        print("Restore failed")
        return

    data = r.json()
    content = data["files"]["backup.json"]["content"]

    users = json.loads(content)

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    for u in users:
        cur.execute("""
        INSERT OR REPLACE INTO users
        (username, password_hash, public_key, encrypted_private_key)
        VALUES (?, ?, ?, ?)
        """, (
            u["username"],
            u["password_hash"],
            u["public_key"],
            u["encrypted_private_key"]
        ))

    conn.commit()
    conn.close()

    print("Restore complete")

# ==============================
# ADD USER (AUTO BACKUP)
# ==============================

@app.route("/add_user", methods=["POST"])
def add_user():

    data = request.json

    username = data["username"]
    password_hash = data["password_hash"]
    public_key = data["public_key"]
    encrypted_private_key = data["encrypted_private_key"]

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    INSERT OR REPLACE INTO users
    (username, password_hash, public_key, encrypted_private_key)
    VALUES (?, ?, ?, ?)
    """, (
        username,
        password_hash,
        public_key,
        encrypted_private_key
    ))

    conn.commit()
    conn.close()

    # 🔥 AUTO BACKUP EVERY TIME USER IS CREATED
    backup_to_gist()

    return jsonify({"status": "user added and backed up"})

# ==============================
# VIEW USERS
# ==============================

@app.route("/users", methods=["GET"])
def users():

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT username, public_key FROM users")

    rows = cur.fetchall()
    conn.close()

    return jsonify(rows)

# ==============================
# HOME ROUTE
# ==============================

@app.route("/")
def home():
    return "Server Running"

# ==============================
# STARTUP
# ==============================

if __name__ == "__main__":

    init_db()
    restore_from_gist()

    app.run(host="0.0.0.0", port=5000, debug=True)
