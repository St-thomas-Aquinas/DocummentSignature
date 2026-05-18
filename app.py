import os
import uuid
import hashlib
import requests

from flask import Flask, request, send_from_directory
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client

from pypdf import PdfReader, PdfWriter

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# =========================
# CONFIG
# =========================

app = Flask(__name__)

TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")

client = Client(TWILIO_SID, TWILIO_TOKEN)

UPLOAD_DIR = "uploads"
SIGNED_DIR = "signed"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

sessions = {}

# =========================
# DOWNLOAD FILE
# =========================

def download_file(url, path):
    r = requests.get(url, auth=(TWILIO_SID, TWILIO_TOKEN))
    with open(path, "wb") as f:
        f.write(r.content)

# =========================
# KEY DERIVATION FROM PASSWORD
# =========================

def generate_keypair_from_secret(secret: str):
    """
    Turn "Max124wells" into deterministic private key
    """

    seed = hashlib.sha256(secret.encode()).digest()

    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    public_key = private_key.public_key()

    return private_key, public_key

# =========================
# SIGN DOCUMENT
# =========================

def sign_document(pdf_path, secret):

    private_key, public_key = generate_keypair_from_secret(secret)

    # read file
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    doc_hash = hashlib.sha256(pdf_bytes).digest()

    signature = private_key.sign(doc_hash)

    signature_hex = signature.hex()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    # write pdf
    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for p in reader.pages:
        writer.add_page(p)

    metadata = reader.metadata or {}

    metadata.update({
        "/Signature": signature_hex,
        "/DocumentHash": doc_hash.hex(),
        "/PublicKey": public_key_bytes,
        "/Algorithm": "Ed25519-SHA256"
    })

    writer.add_metadata(metadata)

    out_name = f"signed_{uuid.uuid4().hex}.pdf"
    out_path = os.path.join(SIGNED_DIR, out_name)

    with open(out_path, "wb") as f:
        writer.write(f)

    return out_name

# =========================
# SERVE FILE
# =========================

@app.route("/signed/<filename>")
def serve_file(filename):
    return send_from_directory(SIGNED_DIR, filename, as_attachment=True)

# =========================
# WEBHOOK
# =========================

@app.route("/webhook", methods=["POST"])
def webhook():

    msg = request.values.get("Body", "").strip()
    from_user = request.values.get("From")
    num_media = int(request.values.get("NumMedia", 0))

    resp = MessagingResponse()
    reply = resp.message()

    # STEP 1: RECEIVE PDF
    if num_media > 0:

        media_url = request.values.get("MediaUrl0")
        media_type = request.values.get("MediaContentType0")

        if media_type != "application/pdf":
            reply.body("Send PDF only.")
            return str(resp)

        filename = f"{uuid.uuid4().hex}.pdf"
        path = os.path.join(UPLOAD_DIR, filename)

        download_file(media_url, path)

        sessions[from_user] = {
            "pdf": path,
            "stage": "awaiting_secret"
        }

        reply.body("PDF received.\nNow type your secret key (e.g. Max124wells)")
        return str(resp)

    # STEP 2: RECEIVE SECRET
    if from_user in sessions:

        session = sessions[from_user]

        if session["stage"] == "awaiting_secret":

            try:
                secret = msg
                pdf_path = session["pdf"]

                signed_file = sign_document(pdf_path, secret)

                public_url = request.host_url + "signed/" + signed_file

                client.messages.create(
                    from_="whatsapp:+14155238886",
                    to=from_user,
                    body="Signed document ready ✅",
                    media_url=[public_url]
                )

                del sessions[from_user]

                reply.body("Done. Check your WhatsApp file.")
                return str(resp)

            except Exception as e:
                reply.body(f"Error: {str(e)}")
                return str(resp)

    reply.body("Send a PDF to begin.")
    return str(resp)

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
