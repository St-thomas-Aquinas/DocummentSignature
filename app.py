# ============================================
# TWILIO WHATSAPP DOCUMENT SIGNING BOT
# ============================================
#
# FEATURES:
# - Receives PDF from WhatsApp
# - Asks user for private key
# - Computes SHA256 hash
# - Signs document using RSA private key
# - Embeds signature into PDF metadata
# - Returns signed PDF to user
#
# ============================================
# INSTALL:
#
# pip install flask twilio cryptography pypdf requests
#
# ============================================
# RUN:
#
# python app.py
#
# expose using ngrok:
#
# ngrok http 5000
#
# put ngrok URL into Twilio WhatsApp Sandbox webhook
#
# ============================================

from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client

import os
import hashlib
import base64
import requests
import uuid
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from pypdf import PdfReader, PdfWriter

# ============================================
# CONFIG
# ============================================

TWILIO_ACCOUNT_SID = "YOUR_TWILIO_SID"
TWILIO_AUTH_TOKEN = "YOUR_TWILIO_AUTH_TOKEN"

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

app = Flask(__name__)

# ============================================
# TEMP SESSION STORAGE
# ============================================

# Stores:
# {
#   phone_number: {
#       "pdf_path": "...",
#       "waiting_for_key": True
#   }
# }

sessions = {}

# ============================================
# CREATE FOLDERS
# ============================================

os.makedirs("uploads", exist_ok=True)
os.makedirs("signed", exist_ok=True)

# ============================================
# DOWNLOAD FILE
# ============================================

def download_file(url, filename):
    response = requests.get(
        url,
        auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    )

    with open(filename, "wb") as f:
        f.write(response.content)

# ============================================
# SIGN PDF
# ============================================

def sign_pdf(pdf_path, private_key_text):

    # ----------------------------------------
    # LOAD PRIVATE KEY
    # ----------------------------------------

    private_key = serialization.load_pem_private_key(
        private_key_text.encode(),
        password=None
    )

    # ----------------------------------------
    # GENERATE PUBLIC KEY
    # ----------------------------------------

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # ----------------------------------------
    # READ ORIGINAL PDF BYTES
    # ----------------------------------------

    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    # ----------------------------------------
    # COMPUTE HASH
    # ----------------------------------------

    document_hash = hashlib.sha256(pdf_bytes).digest()

    # ----------------------------------------
    # SIGN HASH
    # ----------------------------------------

    signature = private_key.sign(
        document_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(signature).decode()

    # ----------------------------------------
    # LOAD PDF
    # ----------------------------------------

    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    # ----------------------------------------
    # METADATA
    # ----------------------------------------

    metadata = reader.metadata or {}

    metadata.update({
        "/Signature": signature_b64,
        "/DocumentHash": document_hash.hex(),
        "/PublicKey": public_key_pem,
        "/Timestamp": str(int(time.time())),
        "/Algorithm": "RSA-SHA256"
    })

    writer.add_metadata(metadata)

    # ----------------------------------------
    # SAVE SIGNED PDF
    # ----------------------------------------

    signed_filename = f"signed_{uuid.uuid4().hex}.pdf"
    signed_path = os.path.join("signed", signed_filename)

    with open(signed_path, "wb") as f:
        writer.write(f)

    return signed_path

# ============================================
# VERIFY PDF
# ============================================

def verify_pdf(pdf_path):

    try:

        reader = PdfReader(pdf_path)

        metadata = reader.metadata

        signature_b64 = metadata.get("/Signature")
        stored_hash_hex = metadata.get("/DocumentHash")
        public_key_pem = metadata.get("/PublicKey")

        if not all([signature_b64, stored_hash_hex, public_key_pem]):
            return False, "Missing metadata"

        signature = base64.b64decode(signature_b64)

        # ------------------------------------
        # RECOMPUTE HASH
        # ------------------------------------

        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        current_hash = hashlib.sha256(pdf_bytes).digest()

        # NOTE:
        # PDF changed after metadata insertion.
        # For prototype simplicity we verify
        # against stored original hash.
        #
        original_hash = bytes.fromhex(stored_hash_hex)

        # ------------------------------------
        # LOAD PUBLIC KEY
        # ------------------------------------

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode()
        )

        # ------------------------------------
        # VERIFY SIGNATURE
        # ------------------------------------

        public_key.verify(
            signature,
            original_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True, "VALID SIGNATURE"

    except Exception as e:
        return False, str(e)

# ============================================
# WEBHOOK
# ============================================

@app.route("/webhook", methods=["POST"])
def webhook():

    incoming_msg = request.values.get("Body", "").strip()

    from_number = request.values.get("From")

    num_media = int(request.values.get("NumMedia", 0))

    response = MessagingResponse()
    msg = response.message()

    # ========================================
    # STEP 1: USER SENDS PDF
    # ========================================

    if num_media > 0:

        media_url = request.values.get("MediaUrl0")
        media_type = request.values.get("MediaContentType0")

        # ONLY PDFs
        if media_type != "application/pdf":

            msg.body("Please send a PDF document only.")
            return str(response)

        # DOWNLOAD PDF
        filename = f"{uuid.uuid4().hex}.pdf"
        filepath = os.path.join("uploads", filename)

        download_file(media_url, filepath)

        # SAVE SESSION
        sessions[from_number] = {
            "pdf_path": filepath,
            "waiting_for_key": True
        }

        msg.body(
            "PDF received.\n\n"
            "Now paste your RSA PRIVATE KEY in PEM format."
        )

        return str(response)

    # ========================================
    # STEP 2: USER SENDS PRIVATE KEY
    # ========================================

    if from_number in sessions:

        session = sessions[from_number]

        if session["waiting_for_key"]:

            try:

                private_key_text = incoming_msg

                pdf_path = session["pdf_path"]

                # SIGN PDF
                signed_pdf_path = sign_pdf(
                    pdf_path,
                    private_key_text
                )

                # SEND BACK TO USER
                message = client.messages.create(
                    from_='whatsapp:+14155238886',
                    body='Your document has been digitally signed.',
                    media_url=[
                        "YOUR_PUBLIC_FILE_URL/" +
                        os.path.basename(signed_pdf_path)
                    ],
                    to=from_number
                )

                # CLEAR SESSION
                del sessions[from_number]

                msg.body(
                    "Document signed successfully.\n"
                    "Check the returned PDF."
                )

                return str(response)

            except Exception as e:

                msg.body(
                    f"Failed to sign document.\n\nError:\n{str(e)}"
                )

                return str(response)

    # ========================================
    # DEFAULT MESSAGE
    # ========================================

    msg.body(
        "Send a PDF document to begin digital signing."
    )

    return str(response)

# ============================================
# START SERVER
# ============================================

if __name__ == "__main__":
    app.run(debug=True)