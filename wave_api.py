from flask import Flask, request, jsonify, session
from flask_cors import CORS
import os, json, time, uuid, shutil, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.urandom(32)

# Directories
KEYS_DIR = "extension_wave_keys"
MESSAGES_DIR = "extension_wave_messages"
CONTACTS_DIR = "extension_wave_contacts"

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(MESSAGES_DIR, exist_ok=True)
os.makedirs(CONTACTS_DIR, exist_ok=True)

def derive_key(password: str, salt: bytes):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password.encode())

def store_private_key(username, private_key, password):
    import secrets
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    # Encrypt using the 16-byte salt as nonce (as used in the client)
    encrypted_private_key = aesgcm.encrypt(salt, private_key, None)
    data = {
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "encrypted_key": base64.urlsafe_b64encode(encrypted_private_key).decode()
    }
    with open(f"{KEYS_DIR}/{username}_private.json", "w") as f:
        json.dump(data, f)

def load_private_key_file(username):
    path = f"{KEYS_DIR}/{username}_private.json"
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)

def load_public_key(username):
    path = f"{KEYS_DIR}/{username}_public.key"
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()

def get_folder(pubkey_b64):
    folder = hashlib.sha256(pubkey_b64.encode()).hexdigest()[:16]
    return os.path.join(MESSAGES_DIR, folder)

@app.route("/")
def home():
    return {
        "message": "Wave API with public-key-based routing",
        "endpoints": [
            "/session_status (GET)",
            "/register (POST)",
            "/login (POST)",
            "/logout (POST)",
            "/get_public_key (GET)",
            "/get_encrypted_private_key (GET)",
            "/send_message (POST)",
            "/get_messages (GET)",
            "/add_contact (POST)",
            "/get_contacts (GET)",
            "/remove_contact (POST)",
            "/delete_account (POST)"
        ]
    }

@app.route("/session_status", methods=["GET"])
def session_status():
    if "user" in session and "pubkey_b64" in session:
        return jsonify({"logged_in": True, "username": session["user"]})
    else:
        return jsonify({"logged_in": False, "username": None})

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    if os.path.exists(f"{KEYS_DIR}/{username}_public.key"):
        return jsonify({"success": False, "error": "User already exists"}), 400

    try:
        import oqs
        with oqs.KeyEncapsulation("Kyber512") as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
        with open(f"{KEYS_DIR}/{username}_public.key", "wb") as f:
            f.write(public_key)
        store_private_key(username, private_key, password)
        pubkey_b64 = base64.urlsafe_b64encode(public_key).decode()
        session["user"] = username
        session["pubkey_b64"] = pubkey_b64
        return jsonify({"success": True, "message": f"User {username} registered"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Registration failed: {str(e)}"}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if not os.path.exists(f"{KEYS_DIR}/{username}_public.key"):
        return jsonify({"success": False, "error": "User does not exist"}), 401
    if not os.path.exists(f"{KEYS_DIR}/{username}_private.json"):
        return jsonify({"success": False, "error": "No private key file found"}), 401

    pubkey = load_public_key(username)
    if not pubkey:
        return jsonify({"success": False, "error": "Could not load public key"}), 500
    pubkey_b64 = base64.urlsafe_b64encode(pubkey).decode()
    session["user"] = username
    session["pubkey_b64"] = pubkey_b64
    return jsonify({"success": True, "message": f"User {username} logged in"}), 200

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    session.pop("pubkey_b64", None)
    return jsonify({"success": True, "message": "Logged out"}), 200

@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    if "user" not in session or "pubkey_b64" not in session:
        return jsonify({"error": "Not logged in"}), 401
    return jsonify({"public_key": session["pubkey_b64"]}), 200

@app.route("/get_encrypted_private_key", methods=["GET"])
def get_encrypted_private_key():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401
    enc_file = load_private_key_file(session["user"])
    if not enc_file:
        return jsonify({"error": "Private key file not found"}), 404
    return jsonify({"encrypted_private_key": enc_file}), 200

@app.route("/send_message", methods=["POST"])
def send_message():
    if "user" not in session or "pubkey_b64" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.json
    sender_pubkey_b64 = session["pubkey_b64"]
    recipient_pubkey_b64 = data.get("recipient_pubkey")
    # Fields for recipient encryption
    ciphertext_kem = data.get("ciphertext_kem")
    ciphertext_msg = data.get("ciphertext_msg")
    nonce = data.get("nonce")
    # Fields for sender encryption
    sender_ciphertext_kem = data.get("sender_ciphertext_kem")
    sender_ciphertext_msg = data.get("sender_ciphertext_msg")
    sender_nonce = data.get("sender_nonce")

    if (not recipient_pubkey_b64 or not ciphertext_kem or not ciphertext_msg or not nonce or
        not sender_ciphertext_kem or not sender_ciphertext_msg or not sender_nonce):
        return jsonify({"success": False, "error": "All encrypted message data required"}), 400

    try:
        _ = base64.urlsafe_b64decode(recipient_pubkey_b64)
    except Exception as e:
        return jsonify({"error": "Invalid base64 for recipient pubkey"}), 400

    message_id = str(uuid.uuid4())
    timestamp = time.time()

    # Derive folder names from the public keys.
    sender_folder = hashlib.sha256(sender_pubkey_b64.encode()).hexdigest()[:16]
    recipient_folder = hashlib.sha256(recipient_pubkey_b64.encode()).hexdigest()[:16]

    # Save recipient copy (encrypted for recipient).
    recipient_dir = os.path.join(MESSAGES_DIR, recipient_folder)
    os.makedirs(recipient_dir, exist_ok=True)
    recipient_msg_data = {
        "message_id": message_id,
        "sender_pubkey_b64": sender_pubkey_b64,
        "recipient_pubkey_b64": recipient_pubkey_b64,
        "ciphertext_kem": ciphertext_kem,
        "ciphertext_msg": ciphertext_msg,
        "nonce": nonce,
        "timestamp": timestamp
    }
    with open(os.path.join(recipient_dir, f"{message_id}.json"), "w") as f:
        json.dump(recipient_msg_data, f)

    # Save sender copy (encrypted for sender).
    sender_dir = os.path.join(MESSAGES_DIR, sender_folder)
    os.makedirs(sender_dir, exist_ok=True)
    sender_msg_data = {
        "message_id": message_id,
        "sender_pubkey_b64": sender_pubkey_b64,
        "recipient_pubkey_b64": recipient_pubkey_b64,
        # IMPORTANT: For the sender copy, use the sender-specific ephemeral data,
        # but store them under the same keys so the client decryption logic works.
        "ciphertext_kem": sender_ciphertext_kem,
        "ciphertext_msg": sender_ciphertext_msg,
        "nonce": sender_nonce,
        "timestamp": timestamp
    }
    with open(os.path.join(sender_dir, f"{message_id}.json"), "w") as f:
        json.dump(sender_msg_data, f)

    return jsonify({"success": True, "message": "Message sent"}), 200

@app.route("/get_messages", methods=["GET"])
def get_messages():
    if "user" not in session or "pubkey_b64" not in session:
        return jsonify({"error": "Not logged in"}), 401

    user_pubkey_b64 = session["pubkey_b64"]
    folder = hashlib.sha256(user_pubkey_b64.encode()).hexdigest()[:16]
    user_dir = os.path.join(MESSAGES_DIR, folder)
    if not os.path.exists(user_dir):
        return jsonify({"messages": []}), 200

    messages = []
    for filename in os.listdir(user_dir):
        filepath = os.path.join(user_dir, filename)
        with open(filepath, "r") as f:
            msg_data = json.load(f)
            messages.append(msg_data)
    return jsonify({"messages": messages}), 200

@app.route("/add_contact", methods=["POST"])
def add_contact():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.json
    contact_public_key = data.get("contact_public_key")
    nickname = data.get("nickname")
    if not contact_public_key or not nickname:
        return jsonify({"success": False, "error": "Missing public key or nickname"}), 400

    username = session["user"]
    contacts_file = os.path.join(CONTACTS_DIR, f"{username}.json")
    if os.path.exists(contacts_file):
        with open(contacts_file, "r") as f:
            contacts = json.load(f)
    else:
        contacts = {}

    contacts[contact_public_key] = {"nickname": nickname}
    with open(contacts_file, "w") as f:
        json.dump(contacts, f, indent=2)

    return jsonify({"success": True, "message": f"Contact {nickname} added"}), 200

@app.route("/get_contacts", methods=["GET"])
def get_contacts():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401
    username = session["user"]
    contacts_file = os.path.join(CONTACTS_DIR, f"{username}.json")
    if not os.path.exists(contacts_file):
        return jsonify({"contacts": {}}), 200
    with open(contacts_file, "r") as f:
        contacts = json.load(f)
    return jsonify({"contacts": contacts}), 200

@app.route("/remove_contact", methods=["POST"])
def remove_contact():
    if "user" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    data = request.json
    contact_pubkey = data.get("contact_public_key")
    if not contact_pubkey:
        return jsonify({"success": False, "error": "No contact public key"}), 400
    username = session["user"]
    contacts_file = os.path.join(CONTACTS_DIR, f"{username}.json")
    if not os.path.exists(contacts_file):
        return jsonify({"success": False, "error": "Contacts file not found"}), 404
    with open(contacts_file, "r") as f:
        contacts = json.load(f)
    if contact_pubkey in contacts:
        del contacts[contact_pubkey]
        with open(contacts_file, "w") as f:
            json.dump(contacts, f, indent=2)
        return jsonify({"success": True, "message": "Contact removed"}), 200
    else:
        return jsonify({"success": False, "error": "Contact not found"}), 404

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    username = session["user"]
    pubkey_b64 = session.get("pubkey_b64", "")
    pk_file = os.path.join(KEYS_DIR, f"{username}_private.json")
    pub_file = os.path.join(KEYS_DIR, f"{username}_public.key")
    if os.path.exists(pk_file):
        os.remove(pk_file)
    if os.path.exists(pub_file):
        os.remove(pub_file)
    cfile = os.path.join(CONTACTS_DIR, f"{username}.json")
    if os.path.exists(cfile):
        os.remove(cfile)
    folder = hashlib.sha256(pubkey_b64.encode()).hexdigest()[:16]
    user_dir = os.path.join(MESSAGES_DIR, folder)
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)
    session.pop("user", None)
    session.pop("pubkey_b64", None)
    return jsonify({"success": True, "message": f"Account {username} deleted"}), 200

if __name__ == "__main__":
    app.run(port=5000, debug=True)
