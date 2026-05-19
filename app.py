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

# =========================
# APP CONFIG
# =========================

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================
# DATABASE
# =========================

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

# =========================
# HELPERS
# =========================

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def get_file_hash(file_path):
    """Hash RAW FILE BYTES (works for ALL file types)"""
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).digest()

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

    cursor.execute("""
        INSERT INTO users (username, password_hash, public_key, encrypted_private_key)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        generate_password_hash(password),
        public_bytes.hex(),
        encrypted_private.decode()
    ))

    conn.commit()

# =========================
# LOAD PRIVATE KEY
# =========================

def load_private_key(username, password):

    cursor.execute("""
        SELECT encrypted_private_key FROM users WHERE username=?
    """, (username,))

    row = cursor.fetchone()
    if not row:
        return None

    cipher = Fernet(derive_key(password))
    private_bytes = cipher.decrypt(row[0].encode())

    return Ed25519PrivateKey.from_private_bytes(private_bytes)

# =========================
# SIGN FILE (ALL TYPES)
# =========================

def sign_file(file_path, username, private_key):

    file_hash = get_file_hash(file_path)
    signature = private_key.sign(file_hash)

    cursor.execute("""
        SELECT public_key FROM users WHERE username=?
    """, (username,))

    public_key = cursor.fetchone()[0]

    ext = os.path.splitext(file_path)[1]
    output_name = f"signed_{uuid.uuid4().hex}{ext}"
    output_path = os.path.join(SIGNED_FOLDER, output_name)

    # copy file
    with open(file_path, "rb") as f:
        data = f.read()

    with open(output_path, "wb") as f:
        f.write(data)

    # metadata file
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

# =========================
# VERIFY FILE (ALL TYPES)
# =========================

def verify_file(file_path):

    meta_path = file_path + ".meta"

    if not os.path.exists(meta_path):
        return False, "Missing metadata file"

    try:
        with open(meta_path, "r") as f:
            meta = json.load(f)
    except:
        return False, "Corrupted metadata file"

    signature = bytes.fromhex(meta["signature"])
    stored_hash = bytes.fromhex(meta["hash"])
    public_key_hex = meta["public_key"]
    signer = meta["signer"]

    current_hash = get_file_hash(file_path)

    if current_hash != stored_hash:
        return False, "Document was modified"

    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(public_key_hex)
    )

    try:
        public_key.verify(signature, stored_hash)
        return True, f"VALID SIGNATURE - Signed by {signer}"
    except:
        return False, "INVALID SIGNATURE"

# =========================
# ROUTES
# =========================

@app.route("/")
def home():
    return render_template("index.html")

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        register_user(request.form["username"], request.form["password"])
        flash("Registered successfully")
        return redirect("/login")

    return render_template("register.html")

# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = cursor.fetchone()

        if row and check_password_hash(row[0], password):
            session["username"] = username
            session["password"] = password
            return redirect("/dashboard")

        flash("Invalid credentials")

    return render_template("login.html")

# -------- SIGN FILE --------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    result = None

    if request.method == "POST":

        if "file" not in request.files:
            flash("No file uploaded")
            return redirect("/dashboard")

        file = request.files["file"]

        if file.filename == "":
            flash("No file selected")
            return redirect("/dashboard")

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        private_key = load_private_key(session["username"], session["password"])

        result = sign_file(path, session["username"], private_key)

    return render_template("dashboard.html", result=result)

# -------- VERIFY FILE --------
@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        if "file" not in request.files:
            flash("No file uploaded")
            return redirect("/verify")

        file = request.files["file"]

        path = os.path.join(UPLOAD_FOLDER, f"verify_{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        valid, result = verify_file(path)

    #return render_template("verify.html", result=result)
     return result 

# -------- DOWNLOAD --------
@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(SIGNED_FOLDER, filename, as_attachment=True)

# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
