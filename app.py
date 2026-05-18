import os
import uuid
import hashlib
import base64
import requests

from flask import Flask, request, send_from_directory
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client

from pypdf import PdfReader, PdfWriter

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

# =========================
# APP SETUP
# =========================

app = Flask(__name__)

TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")

client = Client(TWILIO_SID, TWILIO_TOKEN)

UPLOAD_DIR = "uploads"
SIGNED_DIR = "signed"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

# =========================
# DATABASE (simple in-memory)
# =========================

users = {}  
# format:
# users[phone] = {
#   "private_key": ...,
#   "public_key": ...
# }

sessions = {}

# =========================
# DOWNLOAD FILE
# =========================

def download_file(url, path):
    r = requests.get(url, auth=(TWILIO_SID, TWILIO_TOKEN))
    with open(path, "wb") as f:
        f.write(r.content)

# =========================
# REGISTER USER (ASYMMETRIC KEYPAIR)
# =========================

def register_user(phone):

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    users[phone] = {
        "private_key": private_key,
        "public_key": public_key
    }

# =========================
# SIGN DOCUMENT
# =========================

def sign_pdf(pdf_path, private_key):

    with open(pdf_path, "rb") as f:
        data = f.read()

    doc_hash = hashlib.sha256(data).digest()

    signature = private_key.sign(doc_hash)

    return signature, doc_hash

# =========================
# VERIFY DOCUMENT
# =========================

def verify_pdf(pdf_path, public_key, signature_hex, hash_hex):

    with open(pdf_path, "rb") as f:
        data = f.read()

    current_hash = hashlib.sha256(data).digest()

    stored_hash = bytes.fromhex(hash_hex)
    signature = bytes.fromhex(signature_hex)

    if current_hash != stored_hash:
        return False, "Document modified"

    try:
        public_key.verify(signature, stored_hash)
        return True, "VALID SIGNATURE"
    except:
        return False, "INVALID SIGNATURE"

# =========================
# SAVE FILE ROUTE
# =========================

@app.route("/signed/<file>")
def serve(file):
    return send_from_directory(SIGNED_DIR, file, as_attachment=True)

# =========================
# WEBHOOK
# =========================

@app.route("/webhook", methods=["POST"])
def webhook():

    msg = request.values.get("Body", "").strip()
    phone = request.values.get("From")
    num_media = int(request.values.get("NumMedia", 0))

    resp = MessagingResponse()
    reply = resp.message()

    # =========================
    # REGISTER COMMAND
    # =========================

    if msg.lower() == "register":

        register_user(phone)

        reply.body(
            "Account created ✅\n\n"
            "Your asymmetric keypair is ready.\n"
            "Send a PDF to sign."
        )
        return str(resp)

    # =========================
    # PDF RECEIVED
    # =========================

    if num_media > 0:

        if phone not in users:
            reply.body("Send REGISTER first.")
            return str(resp)

        media_url = request.values.get("MediaUrl0")

        filename = f"{uuid.uuid4().hex}.pdf"
        path = os.path.join(UPLOAD_DIR, filename)

        download_file(media_url, path)

        private_key = users[phone]["private_key"]

        signature, doc_hash = sign_pdf(path, private_key)

        public_key = users[phone]["public_key"]

        # save metadata
        reader = PdfReader(path)
        writer = PdfWriter()

        for p in reader.pages:
            writer.add_page(p)

        metadata = reader.metadata or {}

        metadata.update({
            "/Signature": signature.hex(),
            "/DocumentHash": doc_hash.hex(),
            "/PublicKey": public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex(),
            "/Algorithm": "Ed25519"
        })

        writer.add_metadata(metadata)

        out_name = f"signed_{uuid.uuid4().hex}.pdf"
        out_path = os.path.join(SIGNED_DIR, out_name)

        with open(out_path, "wb") as f:
            writer.write(f)

        url = request.host_url + "signed/" + out_name

        client.messages.create(
            from_="whatsapp:+14155238886",
            to=phone,
            body="Signed document ready ✅",
            media_url=[url]
        )

        reply.body("Processing done.")
        return str(resp)

    # =========================
    # DEFAULT
    # =========================

    reply.body("Send REGISTER or a PDF.")
    return str(resp)

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
