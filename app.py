import os
import uuid
import hashlib
import base64
import requests
from flask import Flask, request, send_from_directory
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from pypdf import PdfReader, PdfWriter

# =========================
# CONFIG
# =========================

app = Flask(__name__)

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# Simple session store (use DB in production)
sessions = {}

# =========================
# DOWNLOAD FILE FROM TWILIO
# =========================

def download_file(url, filename):
    response = requests.get(url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN))
    with open(filename, "wb") as f:
        f.write(response.content)

# =========================
# SIGN PDF
# =========================

def sign_pdf(pdf_path, private_key_text):

    private_key = serialization.load_pem_private_key(
        private_key_text.encode(),
        password=None
    )

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Read file bytes
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    # Hash document
    document_hash = hashlib.sha256(pdf_bytes).digest()

    # Sign hash
    signature = private_key.sign(
        document_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(signature).decode()

    # Write signed PDF
    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    metadata = reader.metadata or {}

    metadata.update({
        "/Signature": signature_b64,
        "/DocumentHash": document_hash.hex(),
        "/PublicKey": public_key_pem,
        "/Algorithm": "RSA-SHA256"
    })

    writer.add_metadata(metadata)

    signed_filename = f"signed_{uuid.uuid4().hex}.pdf"
    signed_path = os.path.join(SIGNED_FOLDER, signed_filename)

    with open(signed_path, "wb") as f:
        writer.write(f)

    return signed_filename

# =========================
# SERVE SIGNED FILE
# =========================

@app.route("/signed/<filename>")
def serve_file(filename):
    return send_from_directory(SIGNED_FOLDER, filename, as_attachment=True)

# =========================
# WEBHOOK
# =========================

@app.route("/webhook", methods=["POST"])
def webhook():

    msg_body = request.values.get("Body", "").strip()
    from_number = request.values.get("From")
    num_media = int(request.values.get("NumMedia", 0))

    resp = MessagingResponse()
    reply = resp.message()

    # =========================
    # STEP 1: RECEIVE PDF
    # =========================

    if num_media > 0:

        media_url = request.values.get("MediaUrl0")
        media_type = request.values.get("MediaContentType0")

        if media_type != "application/pdf":
            reply.body("❌ Please send a PDF file only.")
            return str(resp)

        filename = f"{uuid.uuid4().hex}.pdf"
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        download_file(media_url, filepath)

        sessions[from_number] = {
            "pdf_path": filepath,
            "stage": "awaiting_key"
        }

        reply.body("📄 PDF received.\n\n🔑 Now paste your RSA PRIVATE KEY (PEM format).")
        return str(resp)

    # =========================
    # STEP 2: RECEIVE PRIVATE KEY
    # =========================

    if from_number in sessions:

        session = sessions[from_number]

        if session["stage"] == "awaiting_key":

            try:
                private_key_text = msg_body
                pdf_path = session["pdf_path"]

                signed_filename = sign_pdf(pdf_path, private_key_text)

                public_url = request.host_url + "signed/" + signed_filename

                # Send back file
                client.messages.create(
                    from_="whatsapp:+14155238886",
                    to=from_number,
                    body="✅ Your document has been signed successfully.",
                    media_url=[public_url]
                )

                del sessions[from_number]

                reply.body("📤 Signed document sent back to you.")
                return str(resp)

            except Exception as e:
                reply.body(f"❌ Signing failed:\n{str(e)}")
                return str(resp)

    # =========================
    # DEFAULT
    # =========================

    reply.body("📎 Send a PDF document to begin signing.")
    return str(resp)

# =========================
# RUN APP
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
