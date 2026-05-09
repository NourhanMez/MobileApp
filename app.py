
from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, json, hashlib, base64, secrets, time
from datetime import datetime

app = Flask(__name__, static_folder='static')

# ─── In-memory stores ────────────────────────────────────────────────────────
USERS    = {}   # username -> { password_hash, public_key_pem, private_key_pem }
MESSAGES = []   # list of message dicts
SESSIONS = {}   # token -> username

# ─── PKI Helpers ─────────────────────────────────────────────────────────────

def generate_rsa_keypair():
    """Generate RSA-2048 keypair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    return pub_pem, priv_pem


def rsa_encrypt_key(aes_key: bytes, pub_pem: str) -> str:
    """Encrypt AES session key with recipient's RSA public key (OAEP)."""
    pub = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
    enc = pub.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(enc).decode()


def rsa_decrypt_key(enc_key_b64: str, priv_pem: str) -> bytes:
    """Decrypt AES session key with recipient's RSA private key."""
    priv = serialization.load_pem_private_key(
        priv_pem.encode(), password=None, backend=default_backend())
    return priv.decrypt(base64.b64decode(enc_key_b64), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))


def rsa_sign(data: str, priv_pem: str) -> str:
    """Sign data with sender's RSA private key (PSS-SHA256)."""
    priv = serialization.load_pem_private_key(
        priv_pem.encode(), password=None, backend=default_backend())
    sig = priv.sign(data.encode(), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return base64.b64encode(sig).decode()


def rsa_verify(data: str, sig_b64: str, pub_pem: str) -> bool:
    """Verify RSA-PSS signature."""
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
        pub.verify(base64.b64decode(sig_b64), data.encode(), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception:
        return False


def aes_encrypt(plaintext: str, key: bytes) -> tuple[str, str]:
    """AES-256-CBC encrypt; returns (ciphertext_b64, iv_b64)."""
    iv = os.urandom(16)
    # PKCS7 padding
    data = plaintext.encode()
    pad  = 16 - len(data) % 16
    data += bytes([pad] * pad)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = enc.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()


def aes_decrypt(ct_b64: str, iv_b64: str, key: bytes) -> str:
    """AES-256-CBC decrypt."""
    ct = base64.b64decode(ct_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data = decryptor.update(ct) + decryptor.finalize()
    pad = data[-1]
    return data[:-pad].decode()


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def get_user_from_token(token: str):
    return SESSIONS.get(token)


def fingerprint(pub_pem: str) -> str:
    h = hashlib.sha256(pub_pem.encode()).hexdigest()
    return ' '.join(h[i:i+4].upper() for i in range(0, 20, 4))


# ─── Auth routes ─────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if username in USERS:
        return jsonify({'error': 'Username already taken'}), 409
    pub, priv = generate_rsa_keypair()
    USERS[username] = {
        'password_hash': hash_password(password),
        'public_key':    pub,
        'private_key':   priv,
        'fingerprint':   fingerprint(pub),
        'created_at':    datetime.now().isoformat(),
    }
    token = secrets.token_hex(32)
    SESSIONS[token] = username
    return jsonify({
        'token':       token,
        'username':    username,
        'public_key':  pub,
        'private_key': priv,
        'fingerprint': USERS[username]['fingerprint'],
    })


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    user = USERS.get(username)
    if not user or user['password_hash'] != hash_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = secrets.token_hex(32)
    SESSIONS[token] = username
    return jsonify({
        'token':       token,
        'username':    username,
        'public_key':  user['public_key'],
        'private_key': user['private_key'],
        'fingerprint': user['fingerprint'],
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    SESSIONS.pop(token, None)
    return jsonify({'ok': True})


# ─── Users routes ─────────────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
def list_users():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    me = get_user_from_token(token)
    if not me:
        return jsonify({'error': 'Unauthorized'}), 401
    contacts = [
        {'username': u, 'public_key': USERS[u]['public_key'],
         'fingerprint': USERS[u]['fingerprint']}
        for u in USERS if u != me
    ]
    return jsonify({'users': contacts})


# ─── Message routes ───────────────────────────────────────────────────────────

@app.route('/api/send', methods=['POST'])
def send_message():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    sender = get_user_from_token(token)
    if not sender:
        return jsonify({'error': 'Unauthorized'}), 401

    data      = request.json
    recipient = data.get('recipient')
    plaintext = data.get('message', '')
    read_only = data.get('read_only', False)
    ttl       = data.get('ttl', None)         # self-destruct seconds
    encrypt   = data.get('encrypt', True)

    if recipient not in USERS:
        return jsonify({'error': 'Recipient not found'}), 404
    if not plaintext:
        return jsonify({'error': 'Empty message'}), 400

    msg_id = secrets.token_hex(8)

    if encrypt:
        # Step 1 — Generate random AES-256 session key (symmetric)
        aes_key = os.urandom(32)

        # Step 2 — Encrypt plaintext with AES-256-CBC
        ciphertext, iv = aes_encrypt(plaintext, aes_key)

        # Step 3 — Encrypt AES key with recipient's RSA public key (asymmetric)
        enc_key = rsa_encrypt_key(aes_key, USERS[recipient]['public_key'])

        # Step 4 — Sign the ciphertext with sender's RSA private key
        signature = rsa_sign(ciphertext, USERS[sender]['private_key'])

        msg = {
            'id':          msg_id,
            'sender':      sender,
            'recipient':   recipient,
            'ciphertext':  ciphertext,
            'iv':          iv,
            'enc_key':     enc_key,
            'signature':   signature,
            'encrypted':   True,
            'read_only':   read_only,
            'ttl':         ttl,
            'timestamp':   time.time(),
            'created_at':  datetime.now().isoformat(),
        }
    else:
        msg = {
            'id':         msg_id,
            'sender':     sender,
            'recipient':  recipient,
            'plaintext':  plaintext,
            'encrypted':  False,
            'read_only':  read_only,
            'ttl':        ttl,
            'timestamp':  time.time(),
            'created_at': datetime.now().isoformat(),
        }

    MESSAGES.append(msg)
    return jsonify({'ok': True, 'id': msg_id})


@app.route('/api/messages', methods=['GET'])
def get_messages():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    me = get_user_from_token(token)
    if not me:
        return jsonify({'error': 'Unauthorized'}), 401

    contact = request.args.get('contact')
    now = time.time()

    result = []
    for m in MESSAGES:
        # filter thread
        if not ((m['sender'] == me and m['recipient'] == contact) or
                (m['sender'] == contact and m['recipient'] == me)):
            continue
        # TTL check
        if m.get('ttl') and (now - m['timestamp']) > m['ttl']:
            continue

        if m['encrypted']:
            # Decrypt only for the recipient
            if m['recipient'] == me:
                try:
                    aes_key   = rsa_decrypt_key(m['enc_key'], USERS[me]['private_key'])
                    plaintext = aes_decrypt(m['ciphertext'], m['iv'], aes_key)
                    verified  = rsa_verify(m['ciphertext'], m['signature'],
                                           USERS[m['sender']]['public_key'])
                    result.append({
                        'id':         m['id'],
                        'sender':     m['sender'],
                        'recipient':  m['recipient'],
                        'text':       plaintext,
                        'encrypted':  True,
                        'verified':   verified,
                        'read_only':  m['read_only'],
                        'ttl':        m.get('ttl'),
                        'timestamp':  m['timestamp'],
                        'created_at': m['created_at'],
                    })
                except Exception as e:
                    result.append({**m, 'text': '[Decryption error]', 'verified': False})
            else:
                # Sender sees their own message
                result.append({
                    'id':        m['id'],
                    'sender':    m['sender'],
                    'recipient': m['recipient'],
                    'text':      '[Encrypted — only recipient can read]',
                    'encrypted': True,
                    'verified':  True,
                    'read_only': m['read_only'],
                    'ttl':       m.get('ttl'),
                    'timestamp': m['timestamp'],
                    'created_at':m['created_at'],
                })
        else:
            result.append({
                'id':        m['id'],
                'sender':    m['sender'],
                'recipient': m['recipient'],
                'text':      m['plaintext'],
                'encrypted': False,
                'verified':  False,
                'read_only': m['read_only'],
                'ttl':       m.get('ttl'),
                'timestamp': m['timestamp'],
                'created_at':m['created_at'],
            })

    return jsonify({'messages': sorted(result, key=lambda x: x['timestamp'])})


@app.route('/api/rawmsg/<msg_id>', methods=['GET'])
def raw_message(msg_id):
    """Return raw ciphertext for inspection (demo/educational)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    me = get_user_from_token(token)
    if not me:
        return jsonify({'error': 'Unauthorized'}), 401
    for m in MESSAGES:
        if m['id'] == msg_id and (m['sender'] == me or m['recipient'] == me):
            if m.get('encrypted'):
                return jsonify({
                    'ciphertext': m['ciphertext'][:80] + '…',
                    'iv':         m['iv'],
                    'enc_key':    m['enc_key'][:60] + '…',
                    'signature':  m['signature'][:60] + '…',
                    'algorithm':  'AES-256-CBC + RSA-2048-OAEP + RSA-PSS-SHA256',
                })
    return jsonify({'error': 'Not found'}), 404


# ─── Serve frontend ───────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


if __name__ == '__main__':
    # Seed two demo users
    for uname, pw in [('Nourhan', 'nourhan123'), ('Safa', 'safa123')]:
        pub, priv = generate_rsa_keypair()
        USERS[uname] = {
            'password_hash': hash_password(pw),
            'public_key':    pub,
            'private_key':   priv,
            'fingerprint':   fingerprint(pub),
            'created_at':    datetime.now().isoformat(),
        }
    print("💕 Demo accounts: Nourhan/nourhan123  Safa/safa123")
    app.run(debug=True, port=5000)
