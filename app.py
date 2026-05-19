import os
import uuid
import hashlib
import base64
import json
import psycopg2
import requests

from flask import Flask, render_template, request, redirect, session, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from twilio.twiml.messaging_response import MessagingResponse

# =========================
# APP SETUP
# =========================

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET"

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================
# POSTGRES
# =========================

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

# =========================
# INIT DB
# =========================

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        encrypted_private_key TEXT
    )
    """)

    conn.commit()
    conn.close()

with app.app_context():
    init_db()

# =========================
# HELPERS
# =========================

SIGNATURE_MARKER = b"__SIGNATURE_BLOCK__"

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def get_file_hash(data: bytes):
    return hashlib.sha256(data).digest()

def get_public_key(username):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT public_key FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()

    return row[0]

# =========================
# VERIFY CORE LOGIC
# =========================

def verify_file(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER not in data:
        return False, "No embedded signature found"

    file_data, meta_bytes = data.split(SIGNATURE_MARKER)

    try:
        meta = json.loads(meta_bytes.decode())
    except:
        return False, "Corrupted signature"

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

# =========================
# WHATSAPP WEBHOOK
# =========================

@app.route("/whatsapp", methods=["POST"])
def whatsapp_webhook():

    resp = MessagingResponse()

    media_url = request.form.get("MediaUrl0")
    sender = request.form.get("From")

    if not media_url:
        resp.message("📄 Please send a document to verify (PDF, image, docx).")
        return str(resp)

    try:
        # DOWNLOAD FILE FROM TWILIO
        file_data = requests.get(media_url).content

        filename = f"wa_{uuid.uuid4().hex}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        with open(file_path, "wb") as f:
            f.write(file_data)

        # VERIFY
        valid, message = verify_file(file_path)

        if valid:
            resp.message(f"🔐 VERIFIED SUCCESS\n{message}")
        else:
            resp.message(f"❌ VERIFICATION FAILED\n{message}")

    except Exception as e:
        resp.message(f"❌ Error: {str(e)}")

    return str(resp)

# =========================
# SIMPLE WEB UI (OPTIONAL)
# =========================

@app.route("/")
def home():
    return "Document Verification System Running"

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
