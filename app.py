import os
import uuid
import hashlib
import base64
import json
import psycopg2
import requests

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    flash,
    session,
    send_from_directory
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)

from cryptography.hazmat.primitives import serialization

from twilio.twiml.messaging_response import MessagingResponse

# =========================================
# APP CONFIG
# =========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "CHANGE_THIS_SECRET"
)

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================================
# POSTGRES DATABASE
# =========================================

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require"
    )

# =========================================
# INIT DATABASE
# =========================================

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

# =========================================
# HELPERS
# =========================================

SIGNATURE_MARKER = b"__SIGNATURE_BLOCK__"

def derive_key(password):

    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

def get_file_hash(data: bytes):

    return hashlib.sha256(data).digest()

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

    encrypted_private_key = cipher.encrypt(
        private_bytes
    )

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO users (
        username,
        password_hash,
        public_key,
        encrypted_private_key
    )
    VALUES (%s, %s, %s, %s)
    """, (
        username,
        generate_password_hash(password),
        public_bytes.hex(),
        encrypted_private_key.decode()
    ))

    conn.commit()
    conn.close()

# =========================================
# LOAD PRIVATE KEY
# =========================================

def load_private_key(username, password):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT encrypted_private_key
    FROM users
    WHERE username=%s
    """, (username,))

    row = cur.fetchone()

    conn.close()

    cipher = Fernet(derive_key(password))

    private_bytes = cipher.decrypt(
        row[0].encode()
    )

    return Ed25519PrivateKey.from_private_bytes(
        private_bytes
    )

# =========================================
# GET PUBLIC KEY
# =========================================

def get_public_key(username):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT public_key
    FROM users
    WHERE username=%s
    """, (username,))

    row = cur.fetchone()

    conn.close()

    return row[0]

# =========================================
# SIGN FILE
# =========================================

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

    metadata_bytes = json.dumps(metadata).encode()

    extension = os.path.splitext(file_path)[1]

    output_name = f"signed_{uuid.uuid4().hex}{extension}"

    output_path = os.path.join(
        SIGNED_FOLDER,
        output_name
    )

    with open(output_path, "wb") as f:

        f.write(file_data)

        # embed signature block
        f.write(SIGNATURE_MARKER)

        f.write(metadata_bytes)

    return output_name

# =========================================
# VERIFY FILE
# =========================================

def verify_file(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER not in data:
        return False, "No embedded signature found"

    try:

        file_data, metadata_bytes = data.split(
            SIGNATURE_MARKER
        )

        metadata = json.loads(
            metadata_bytes.decode()
        )

    except:
        return False, "Corrupted signature block"

    signature = bytes.fromhex(
        metadata["signature"]
    )

    stored_hash = bytes.fromhex(
        metadata["hash"]
    )

    public_key_hex = metadata["public_key"]

    signer = metadata["signer"]

    # --------------------------------
    # recompute original file hash
    # --------------------------------

    current_hash = get_file_hash(file_data)

    if current_hash != stored_hash:
        return False, "Document was modified"

    # --------------------------------
    # verify cryptographic signature
    # --------------------------------

    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(public_key_hex)
    )

    try:

        public_key.verify(
            signature,
            stored_hash
        )

        return True, f"VALID SIGNATURE - Signed by {signer}"

    except:

        return False, "INVALID SIGNATURE"

# =========================================
# ROUTES
# =========================================

@app.route("/")
def home():
    return render_template("index.html")

# =========================================
# REGISTER
# =========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        try:

            register_user(
                username,
                password
            )

            flash("Registration successful")

            return redirect("/login")

        except Exception as e:

            return f"ERROR: {str(e)}"

    return render_template("register.html")

# =========================================
# LOGIN
# =========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        SELECT password_hash
        FROM users
        WHERE username=%s
        """, (username,))

        row = cur.fetchone()

        conn.close()

        if row and check_password_hash(
            row[0],
            password
        ):

            session["username"] = username
            session["password"] = password

            return redirect("/dashboard")

        flash("Invalid credentials")

    return render_template("login.html")

# =========================================
# DASHBOARD
# =========================================

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    signed_file = None

    if request.method == "POST":

        if "file" not in request.files:

            flash("No file uploaded")
            return redirect("/dashboard")

        uploaded = request.files["file"]

        if uploaded.filename == "":

            flash("Select a file")
            return redirect("/dashboard")

        path = os.path.join(
            UPLOAD_FOLDER,
            f"{uuid.uuid4().hex}_{uploaded.filename}"
        )

        uploaded.save(path)

        private_key = load_private_key(
            session["username"],
            session["password"]
        )

        signed_file = sign_file(
            path,
            session["username"],
            private_key
        )

    return render_template(
        "dashboard.html",
        signed_file=signed_file
    )

# =========================================
# VERIFY WEB
# =========================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        if "file" not in request.files:

            result = "No file uploaded"

            return render_template(
                "verify.html",
                result=result
            )

        uploaded = request.files["file"]

        if uploaded.filename == "":

            result = "No file selected"

            return render_template(
                "verify.html",
                result=result
            )

        path = os.path.join(
            UPLOAD_FOLDER,
            f"verify_{uuid.uuid4().hex}_{uploaded.filename}"
        )

        uploaded.save(path)

        valid, result = verify_file(path)

    return render_template(
        "verify.html",
        result=result
    )

# =========================================
# WHATSAPP VERIFY
# =========================================

@app.route("/whatsapp", methods=["POST"])
def whatsapp_webhook():

    resp = MessagingResponse()

    media_url = request.form.get("MediaUrl0")

    if not media_url:

        resp.message(
            "📄 Please send a signed document to verify."
        )

        return str(resp)

    try:

        # download file from Twilio
        file_data = requests.get(media_url).content

        filename = f"wa_{uuid.uuid4().hex}"

        path = os.path.join(
            UPLOAD_FOLDER,
            filename
        )

        with open(path, "wb") as f:
            f.write(file_data)

        # verify file
        valid, result = verify_file(path)

        if valid:

            resp.message(
                f"🔐 VERIFIED\n\n{result}"
            )

        else:

            resp.message(
                f"❌ INVALID\n\n{result}"
            )

    except Exception as e:

        resp.message(
            f"❌ Error:\n{str(e)}"
        )

    return str(resp)

# =========================================
# DOWNLOAD
# =========================================

@app.route("/download/<filename>")
def download(filename):

    return send_from_directory(
        SIGNED_FOLDER,
        filename,
        as_attachment=True
    )

# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

# =========================================
# START
# =========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
