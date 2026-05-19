import os
import uuid
import sqlite3
import hashlib
import base64

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from pypdf import PdfReader, PdfWriter

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
# REGISTER
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
# SIGN PDF
# =========================================

def sign_pdf(pdf_path, username, private_key):

    reader = PdfReader(pdf_path)

    text_content = ""

    for page in reader.pages:
        text_content += page.extract_text() or ""

    document_hash = hashlib.sha256(
        text_content.encode()
    ).digest()

    signature = private_key.sign(document_hash)

    cursor.execute("""
        SELECT public_key FROM users WHERE username=?
    """, (username,))

    public_key = cursor.fetchone()[0]

    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    metadata = reader.metadata or {}

    metadata.update({
        "/Signature": signature.hex(),
        "/DocumentHash": document_hash.hex(),
        "/PublicKey": public_key,
        "/Signer": username,
        "/Algorithm": "Ed25519"
    })

    writer.add_metadata(metadata)

    output_name = f"signed_{uuid.uuid4().hex}.pdf"
    output_path = os.path.join(SIGNED_FOLDER, output_name)

    with open(output_path, "wb") as f:
        writer.write(f)

    return output_name

# =========================================
# VERIFY PDF (YOUR REQUESTED LOGIC)
# =========================================

def verify_pdf(pdf_path):

    reader = PdfReader(pdf_path)
    metadata = reader.metadata

    if not metadata:
        return False, "No metadata found"

    signature_hex = metadata.get("/Signature")
    stored_hash_hex = metadata.get("/DocumentHash")
    public_key_hex = metadata.get("/PublicKey")
    signer = metadata.get("/Signer")

    if not all([signature_hex, stored_hash_hex, public_key_hex]):
        return False, "Missing metadata"

    signature = bytes.fromhex(signature_hex)
    stored_hash = bytes.fromhex(stored_hash_hex)

    # ======================================================
    # STEP 1: REMOVE SIGNATURE METADATA (LOGICAL ONLY)
    # ======================================================

    ignored_keys = {
        "/Signature",
        "/DocumentHash",
        "/PublicKey",
        "/Signer",
        "/Algorithm"
    }

    # (We do NOT rewrite file, just ignore metadata in logic)

    # ======================================================
    # STEP 2: HASH CLEAN CONTENT (TEXT ONLY)
    # ======================================================

    text_content = ""

    for page in reader.pages:
        text_content += page.extract_text() or ""

    current_hash = hashlib.sha256(
        text_content.encode()
    ).digest()

    # ======================================================
    # STEP 3: CHECK HASH
    # ======================================================

    if current_hash != stored_hash:
        return False, "Document was modified"

    # ======================================================
    # STEP 4: VERIFY SIGNATURE
    # ======================================================

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

        uploaded = request.files["pdf"]

        if uploaded.filename == "":
            flash("Select PDF")
            return redirect(url_for("dashboard"))

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}.pdf")
        uploaded.save(path)

        private_key = load_private_key(
            session["username"],
            session["password"]
        )

        signed_file = sign_pdf(
            path,
            session["username"],
            private_key
        )

    return render_template("dashboard.html", signed_file=signed_file)

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        uploaded = request.files["pdf"]

        path = os.path.join(UPLOAD_FOLDER, f"verify_{uuid.uuid4().hex}.pdf")
        uploaded.save(path)

        valid, result = verify_pdf(path)

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
