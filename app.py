import os
import uuid
import hashlib
import base64
import json
import psycopg2

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

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
# POSTGRES CONFIG (RENDER)
# =========================

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

# =========================
# INIT DB
# =========================

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
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

# =========================
# HELPERS
# =========================

SIGNATURE_MARKER = b"__SIGNATURE_BLOCK__"

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def get_file_hash(data: bytes):
    return hashlib.sha256(data).digest()

# =========================
# REGISTER USER
# =========================

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

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (username, password_hash, public_key, encrypted_private_key)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    """, (
        username,
        generate_password_hash(password),
        public_bytes.hex(),
        encrypted_private.decode()
    ))

    conn.commit()
    conn.close()

# =========================
# LOAD PRIVATE KEY
# =========================

def load_private_key(username, password):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT encrypted_private_key
        FROM users
        WHERE username=%s
    """, (username,))

    row = cursor.fetchone()
    conn.close()

    cipher = Fernet(derive_key(password))
    private_bytes = cipher.decrypt(row[0].encode())

    return Ed25519PrivateKey.from_private_bytes(private_bytes)

# =========================
# GET PUBLIC KEY
# =========================

def get_public_key(username):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT public_key FROM users WHERE username=%s", (username,))
    row = cursor.fetchone()

    conn.close()
    return row[0]

# =========================
# SIGN FILE (EMBEDDED)
# =========================

def sign_file(file_path, username, private_key):

    with open(file_path, "rb") as f:
        file_data = f.read()

    file_hash = get_file_hash(file_data)
    signature = private_key.sign(file_hash)

    public_key = get_public_key(username)

    metadata = {
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": public_key,
        "signer": username,
        "algorithm": "Ed25519"
    }

    meta_bytes = json.dumps(metadata).encode()

    output_name = f"signed_{uuid.uuid4().hex}{os.path.splitext(file_path)[1]}"
    output_path = os.path.join(SIGNED_FOLDER, output_name)

    with open(output_path, "wb") as f:
        f.write(file_data)
        f.write(SIGNATURE_MARKER)
        f.write(meta_bytes)

    return output_name

# =========================
# VERIFY FILE
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
        return False, "Corrupted signature block"

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
# ROUTES (UNCHANGED UI)
# =========================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        register_user(request.form["username"], request.form["password"])
        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
        row = cursor.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            session["username"] = username
            session["password"] = password
            return redirect("/dashboard")

        flash("Invalid login")

    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    result = None

    if request.method == "POST":

        file = request.files["file"]

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        private_key = load_private_key(session["username"], session["password"])

        result = sign_file(path, session["username"], private_key)

    return render_template("dashboard.html", result=result)

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        file = request.files["file"]

        path = os.path.join(UPLOAD_FOLDER, f"verify_{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        valid, result = verify_file(path)

    return render_template("verify.html", result=result)

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(SIGNED_FOLDER, filename, as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# =========================
# START
# =========================

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
