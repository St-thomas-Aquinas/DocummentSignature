import os
import uuid
import sqlite3
import hashlib
import base64
import json
import requests

from flask import Flask, request, jsonify, render_template, redirect, url_for, session

from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# ==============================
# ENV (RENDER SAFE)
# ==============================

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GIST_ID = os.environ.get("GIST_ID")

# ==============================
# FLASK APP
# ==============================

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET"

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

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
# GIST BACKUP SYSTEM
# ==============================

def export_db():

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT username, password_hash, public_key, encrypted_private_key FROM users")
    rows = cur.fetchall()
    conn.close()

    return json.dumps([
        {
            "username": r[0],
            "password_hash": r[1],
            "public_key": r[2],
            "encrypted_private_key": r[3]
        } for r in rows
    ], indent=2)

def backup_to_gist():

    if not GITHUB_TOKEN or not GIST_ID:
        print("Gist backup skipped")
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
        print("Gist backup success")
    else:
        print("Gist backup failed:", r.text)

def restore_from_gist():

    if not GITHUB_TOKEN or not GIST_ID:
        print("Gist restore skipped")
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

    print("Gist restore complete")

# ==============================
# HELPERS
# ==============================

SIGNATURE_MARKER = b"__SIGNATURE_BLOCK__"

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def get_file_hash(data: bytes):
    return hashlib.sha256(data).digest()

# ==============================
# REGISTER USER
# ==============================

def register_user(username, password):

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    cipher = Fernet(derive_key(password))
    encrypted_private = cipher.encrypt(private_bytes)

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO users VALUES (NULL, ?, ?, ?, ?)
    """, (
        username,
        generate_password_hash(password),
        public_bytes.hex(),
        encrypted_private.decode()
    ))

    conn.commit()
    conn.close()

    backup_to_gist()

# ==============================
# LOAD PRIVATE KEY
# ==============================

def load_private_key(username, password):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT encrypted_private_key FROM users WHERE username=?", (username,))
    row = cur.fetchone()

    conn.close()

    cipher = Fernet(derive_key(password))
    private_bytes = cipher.decrypt(row[0].encode())

    return Ed25519PrivateKey.from_private_bytes(private_bytes)

# ==============================
# SIGN FILE (EMBEDDED)
# ==============================

def sign_file(file_path, username, private_key):

    with open(file_path, "rb") as f:
        file_data = f.read()

    file_hash = get_file_hash(file_data)
    signature = private_key.sign(file_hash)

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT public_key FROM users WHERE username=?", (username,))
    public_key = cur.fetchone()[0]
    conn.close()

    meta = {
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": public_key,
        "signer": username
    }

    output_name = f"signed_{uuid.uuid4().hex}{os.path.splitext(file_path)[1]}"
    output_path = os.path.join(SIGNED_FOLDER, output_name)

    with open(output_path, "wb") as f:
        f.write(file_data)
        f.write(SIGNATURE_MARKER)
        f.write(json.dumps(meta).encode())

    return output_name

# ==============================
# VERIFY FILE
# ==============================

def verify_file(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER not in data:
        return False, "No signature found"

    file_data, meta_bytes = data.split(SIGNATURE_MARKER)

    meta = json.loads(meta_bytes.decode())

    signature = bytes.fromhex(meta["signature"])
    stored_hash = bytes.fromhex(meta["hash"])
    public_key_hex = meta["public_key"]
    signer = meta["signer"]

    current_hash = get_file_hash(file_data)

    if current_hash != stored_hash:
        return False, "Document was modified"

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))

    try:
        public_key.verify(signature, stored_hash)
        return True, f"VALID SIGNATURE - Signed by {signer}"
    except:
        return False, "INVALID SIGNATURE"

# ==============================
# ROUTES
# ==============================

@app.route("/")
def home():
    return "Server Running"

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    register_user(data["username"], data["password"])
    return jsonify({"status": "registered"})

@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["file"]
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    private_key = load_private_key("demo", "demo")  # replace with session in real app

    result = sign_file(path, "demo", private_key)

    return jsonify({"file": result})

@app.route("/verify", methods=["POST"])
def verify():

    file = request.files["file"]
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    valid, msg = verify_file(path)

    return jsonify({"valid": valid, "message": msg})

# ==============================
# START
# ==============================

if __name__ == "__main__":
    init_db()
    restore_from_gist()
    app.run(host="0.0.0.0", port=5000, debug=True)
