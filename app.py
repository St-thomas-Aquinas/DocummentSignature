import os
import uuid
import sqlite3
import hashlib
import base64
import json

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# =========================================
# APP CONFIG
# =========================================

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET"

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================================
# DATABASE
# =========================================

conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    public_key TEXT,
    encrypted_private_key TEXT
)
""")

conn.commit()

# =========================================
# HELPERS
# =========================================

def derive_key(password):
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

# =========================================
# RAW FILE HASH (IMPORTANT)
# =========================================

def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).digest()

# =========================================
# REGISTER USER
# =========================================

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
    encrypted_private_key = cipher.encrypt(private_bytes)

    cursor.execute("""
        INSERT INTO users
        (username, password_hash, public_key, encrypted_private_key)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        generate_password_hash(password),
        public_bytes.hex(),
        encrypted_private_key.decode()
    ))

    conn.commit()

# =========================================
# LOAD PRIVATE KEY
# =========================================

def load_private_key(username, password):

    cursor.execute("""
        SELECT encrypted_private_key
        FROM users
        WHERE username=?
    """, (username,))

    row = cursor.fetchone()

    cipher = Fernet(derive_key(password))
    private_bytes = cipher.decrypt(row[0].encode())

    return Ed25519PrivateKey.from_private_bytes(private_bytes)

# =========================================
# SIGN ANY FILE
# =========================================

def sign_document(file_path, username, private_key):

    file_hash = get_file_hash(file_path)

    signature = private_key.sign(file_hash)

    cursor.execute("""
        SELECT public_key FROM users WHERE username=?
    """, (username,))

    public_key = cursor.fetchone()[0]

    output_name = f"signed_{uuid.uuid4().hex}{os.path.splitext(file_path)[1]}"
    output_path = os.path.join(SIGNED_FOLDER, output_name)

    # copy file as-is
    with open(file_path, "rb") as f:
        original = f.read()

    with open(output_path, "wb") as f:
        f.write(original)

    # metadata sidecar file
    meta = {
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": public_key,
        "signer": username,
        "algorithm": "Ed25519"
    }

    with open(output_path + ".meta", "w") as f:
        json.dump(meta, f)

    return output_name

# =========================================
# VERIFY ANY FILE
# =========================================

def verify_file(file_path):

    meta_path = file_path + ".meta"

    if not os.path.exists(meta_path):
        return False, "Missing signature metadata"

    with open(meta_path, "r") as f:
        meta = json.load(f)

    signature = bytes.fromhex(meta["signature"])
    stored_hash = bytes.fromhex(meta["hash"])
    public_key_hex = meta["public_key"]
    signer = meta["signer"]

    current_hash = get_file_hash(file_path)

    # STEP 1: Check file integrity
    if current_hash != stored_hash:
        return False, "Document was modified"

    # STEP 2: Verify signature
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(public_key_hex)
    )

    try:
        public_key.verify(signature, stored_hash)
        return True, f"VALID SIGNATURE - Signed by {signer}"

    except:
        return False, "INVALID SIGNATURE"

# =========================================
# ROUTES
# =========================================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        try:
            register_user(username, password)
            flash("Registration successful")
            return redirect(url_for("login"))
        except Exception as e:
            flash(str(e))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        cursor.execute("""
            SELECT password_hash FROM users WHERE username=?
        """, (username,))

        row = cursor.fetchone()

        if row and check_password_hash(row[0], password):

            session["username"] = username
            session["password"] = password

            return redirect(url_for("dashboard"))

        flash("Invalid credentials")

    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    signed_file = None

    if request.method == "POST":

        uploaded = request.files["file"]

        if uploaded.filename == "":
            flash("Select a file")
            return redirect(url_for("dashboard"))

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{uploaded.filename}")
        uploaded.save(path)

        private_key = load_private_key(
            session["username"],
            session["password"]
        )

        signed_file = sign_document(
            path,
            session["username"],
            private_key
        )

    return render_template("dashboard.html", signed_file=signed_file)

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        uploaded = request.files["file"]

        path = os.path.join(UPLOAD_FOLDER, f"verify_{uuid.uuid4().hex}_{uploaded.filename}")
        uploaded.save(path)

        valid, result = verify_file(path)

    return render_template("verify.html", result=result)

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(SIGNED_FOLDER, filename, as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =========================================
# RUN
# =========================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
