import eventlet
eventlet.monkey_patch()

import os
import json
import secrets
import shutil
import subprocess
import time
import urllib.request as _urllib_req
import base64 as _b64
import shlex
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from flask_socketio import SocketIO, emit
from functools import wraps
from werkzeug.utils import secure_filename

import db as authdb

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

app = Flask(__name__)
# SECRET_KEY: from env in prod; fall back to an ephemeral random key in dev
# (sessions invalidated on each restart, but never a hardcoded value).
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
if not os.environ.get('FLASK_SECRET_KEY'):
    print("⚠️  FLASK_SECRET_KEY non défini dans .env — clé éphémère générée.")
# Cookie hardening — mitige CSRF et vol de cookie.
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# SESSION_COOKIE_SECURE doit rester False tant qu'on tourne en HTTP en LAN.
# Reload des templates sans avoir à restart le service à chaque déploiement.
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)

# --- AUTHENTICATION ---
authdb.init_db(initial_admin_password=os.environ.get('INITIAL_ADMIN_PASSWORD'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"status": "error", "message": "Unauthorized"}), 401
            return redirect(url_for('login'))
        # Force password change before anything else (except the change page itself).
        if session.get('must_change_pw') and request.endpoint != 'change_password':
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"status": "error",
                                "message": "Password change required"}), 403
            return redirect(url_for('change_password'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify({"status": "error", "message": "Admin rights required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def socket_login_required(f):
    """Decorator pour les events socket reservés aux sessions authentifiées (UI admin).
    Les kiosques (endpoint.py / player.html) ne sont pas concernés : ils n'utilisent
    pas ces events admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return  # silently drop unauthenticated calls
        return f(*args, **kwargs)
    return decorated

def _safe_media_path(rel):
    """Résout un chemin relatif sous MEDIA_FOLDER et vérifie qu'il n'en sort pas.
    Renvoie le chemin absolu sécurisé, ou None en cas de tentative de traversée."""
    if not rel or not isinstance(rel, str):
        return None
    media_root = os.path.realpath(MEDIA_FOLDER)
    target = os.path.realpath(os.path.join(MEDIA_FOLDER, rel))
    if target == media_root or target.startswith(media_root + os.sep):
        return target
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr or '?'
        user = (request.form.get('username') or '').strip()
        pw = request.form.get('password') or ''

        if authdb.is_rate_limited(ip):
            return render_template('login.html',
                error="Trop de tentatives. Réessayez dans 15 minutes."), 429

        u = authdb.verify_password(user, pw)
        authdb.record_attempt(ip, user, success=bool(u))
        if not u:
            return render_template('login.html', error="Identifiants invalides")

        authdb.clear_attempts(ip)
        authdb.touch_last_login(user)
        session['logged_in'] = True
        session['username'] = user
        session['is_admin'] = bool(u['is_admin'])
        session['must_change_pw'] = bool(u['must_change_pw'])
        if session['must_change_pw']:
            return redirect(url_for('change_password'))
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password') or ''
        new = request.form.get('new_password') or ''
        confirm = request.form.get('confirm_password') or ''
        username = session.get('username')

        if new != confirm:
            return render_template('change_password.html',
                error="Les deux nouveaux mots de passe ne correspondent pas.")
        if len(new) < 10:
            return render_template('change_password.html',
                error="Le nouveau mot de passe doit faire au moins 10 caractères.")
        if not authdb.verify_password(username, current):
            return render_template('change_password.html',
                error="Mot de passe actuel incorrect.")

        authdb.update_password(username, new)
        session['must_change_pw'] = False
        return redirect(url_for('index'))
    return render_template('change_password.html',
        forced=session.get('must_change_pw', False))

@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    return jsonify({
        u['username']: {
            "role": "admin" if u['is_admin'] else "user",
            "must_change_pw": bool(u['must_change_pw']),
            "last_login": u['last_login'],
        }
        for u in authdb.list_users()
    })

@app.route('/api/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    data = request.json or {}
    new_user = (data.get('username') or '').strip()
    new_pass = data.get('password') or ''
    role = data.get('role', 'user')
    if not new_user or not new_pass:
        return jsonify({"status": "error", "message": "Missing info"}), 400
    if len(new_pass) < 10:
        return jsonify({"status": "error",
                        "message": "Mot de passe trop court (10 caractères min)."}), 400
    if authdb.get_user(new_user):
        return jsonify({"status": "error", "message": "User exists"}), 400

    authdb.create_user(new_user, new_pass,
                      is_admin=(role == 'admin'),
                      must_change_pw=True)
    return jsonify({"status": "success"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
@admin_required
def delete_user():
    data = request.json or {}
    user_to_del = (data.get('username') or '').strip()
    if user_to_del == "IT":
        return jsonify({"status": "error", "message": "Cannot delete root admin"}), 400
    if authdb.delete_user(user_to_del):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "User not found"}), 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

MASTER_IP = os.environ.get('MASTER_IP', '127.0.0.1')
MEDIA_FOLDER = os.path.join(ROOT_DIR, 'media')
SCREENMAP_FILE = os.path.join(BASE_DIR, 'screenmap.json')
FLEET_FILE = os.path.join(BASE_DIR, 'fleet.json')

# SSH : clé (après install.sh) ou fallback password — chargés depuis .env
SSH_KEY_PATH = os.path.expanduser('~/.ssh/disscreen_key')
SSH_KEY_USER = os.environ.get('SSH_KEY_USER', 'screenuser')
SSH_PASS_USER = os.environ.get('SSH_PASS_USER', 'YOUR_SESSION_USER')
SSH_PASS = os.environ.get('SSH_PASS', '')

MASTER_PUBKEY = ""
PDFJS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'pdfjs')

os.makedirs(MEDIA_FOLDER, exist_ok=True)
# Dossiers par défaut créés UNIQUEMENT au premier démarrage (media/ vide).
# Une fois que l'utilisateur a touché à la médiathèque, on ne les recrée plus
# automatiquement — sinon un dossier supprimé reviendrait à chaque restart.
try:
    if not any(os.scandir(MEDIA_FOLDER)):
        for default_f in ['Evenements', 'RH', 'Sensibilisation']:
            os.makedirs(os.path.join(MEDIA_FOLDER, default_f), exist_ok=True)
except OSError:
    pass

def ensure_pdfjs():
    """Télécharge PDF.js + socket.io.js localement au premier démarrage (servi sans CDN)."""
    os.makedirs(PDFJS_DIR, exist_ok=True)
    base = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/'
    for fname in ('pdf.min.js', 'pdf.worker.min.js'):
        dest = os.path.join(PDFJS_DIR, fname)
        if not os.path.exists(dest):
            try:
                print(f"⬇️  Téléchargement PDF.js {fname}…")
                _urllib_req.urlretrieve(base + fname, dest)
                print(f"✅ {fname} OK")
            except Exception as e:
                print(f"⚠️  PDF.js {fname} non disponible : {e}")
    # socket.io client JS — local pour les kiosques sans Internet
    static_dir = os.path.dirname(PDFJS_DIR)
    sio_dest = os.path.join(static_dir, 'socket.io.min.js')
    if not os.path.exists(sio_dest):
        try:
            print("⬇️  Téléchargement socket.io.min.js…")
            _urllib_req.urlretrieve(
                'https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.min.js',
                sio_dest
            )
            print("✅ socket.io.min.js OK")
        except Exception as e:
            print(f"⚠️  socket.io.min.js non disponible : {e}")

ALLOWED_EXT = {
    'png': 'image', 'jpg': 'image', 'jpeg': 'image', 'webp': 'image', 'gif': 'image',
    'mp4': 'video', 'webm': 'video', 'pdf': 'document'
}

# --- ÉTAT DE LA FLOTTE ---
fleet = {"pending": {}, "active": {}, "configs": {}}

def save_fleet():
    """Persiste les endpoints approuvés sur disque."""
    data = {
        "active": {ip: {k: v for k, v in node.items() if k != 'sid'}
                   for ip, node in fleet["active"].items()},
        "configs": fleet["configs"]
    }
    try:
        with open(FLEET_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Erreur sauvegarde fleet: {e}")

def load_fleet():
    """Charge les endpoints approuvés au démarrage du master."""
    if not os.path.exists(FLEET_FILE):
        return
    try:
        with open(FLEET_FILE) as f:
            data = json.load(f)
        for ip, node in data.get("active", {}).items():
            fleet["active"][ip] = {**node, "status": "offline", "sid": ""}
        fleet["configs"].update(data.get("configs", {}))
        print(f"✅ Flotte chargée : {len(fleet['active'])} terminal(s) connu(s)")
    except Exception as e:
        print(f"Erreur chargement fleet: {e}")

# ─── Screenshot CDP ──────────────────────────────────────────────────
_SCREENSHOT_PY = b"""
import socket,base64,json,os,struct,urllib.request,sys
def rf(s):
    h=b''
    while len(h)<2:h+=s.recv(2-len(h))
    n=h[1]&0x7F
    if n==126:
        e=b''
        while len(e)<2:e+=s.recv(2-len(e))
        n=struct.unpack('>H',e)[0]
    elif n==127:
        e=b''
        while len(e)<8:e+=s.recv(8-len(e))
        n=struct.unpack('>Q',e)[0]
    d=b''
    while len(d)<n:d+=s.recv(min(65536,n-len(d)))
    return d
try:
    r=urllib.request.urlopen('http://127.0.0.1:9222/json/list',timeout=3)
    p=[t for t in json.loads(r.read()) if t.get('type')=='page']
    if not p:sys.exit(1)
    path='/'+p[0]['webSocketDebuggerUrl'].split('/',3)[-1]
    s=socket.socket();s.settimeout(12);s.connect(('127.0.0.1',9222))
    k=base64.b64encode(os.urandom(16)).decode()
    s.sendall(('GET '+path+' HTTP/1.1\\r\\nHost: 127.0.0.1:9222\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: '+k+'\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n').encode())
    hs=b''
    while b'\\r\\n\\r\\n' not in hs:hs+=s.recv(512)
    msg=json.dumps({'id':1,'method':'Page.captureScreenshot','params':{'format':'jpeg','quality':40}}).encode()
    mask=os.urandom(4);masked=bytes(b^mask[i%4] for i,b in enumerate(msg));n=len(msg)
    s.sendall((bytes([0x81,0x80|n]) if n<126 else bytes([0x81,0xFE,n>>8,n&0xFF]))+mask+masked)
    print(json.loads(rf(s))['result']['data'])
    s.close()
except Exception as e:sys.stderr.write(str(e));sys.exit(1)
"""
_SCREENSHOT_B64 = _b64.b64encode(_SCREENSHOT_PY).decode()
_screenshot_cache = {}   # ip -> (timestamp, jpeg_bytes)

def get_screenshot(ip):
    now = time.time()
    if ip in _screenshot_cache and now - _screenshot_cache[ip][0] < 8:
        return _screenshot_cache[ip][1]
    
    # Tentative via SSH
    result = ssh_run(ip, f"echo '{_SCREENSHOT_B64}' | base64 -d | python3 2>/dev/null", timeout=15)
    
    # Fallback local si l'IP est celle du Master ou si SSH a échoué
    if result['returncode'] != 0:
        try:
            # Exécution locale du même script de capture
            import subprocess as sp
            res = sp.run(['python3', '-c', _SCREENSHOT_PY.decode()], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                stdout_data = res.stdout.strip()
            else:
                stdout_data = ""
        except Exception:
            stdout_data = ""
    else:
        stdout_data = result['stdout'].strip()

    if stdout_data:
        try:
            data = _b64.b64decode(stdout_data)
            if data:
                _screenshot_cache[ip] = (now, data)
                return data
        except Exception:
            pass
    return None

@app.route('/api/endpoint/<ip>/delete', methods=['DELETE'])
@login_required
def delete_endpoint(ip):
    """Supprime un terminal de la flotte."""
    if ip in fleet["active"]:
        del fleet["active"][ip]
        if ip in fleet["configs"]:
            del fleet["configs"][ip]
        save_fleet()
        socketio.emit('update_ui', fleet)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Terminal non trouvé"}), 404

@app.route('/api/endpoint/<ip>/ssh-reload', methods=['POST'])
@login_required
def ssh_reload_endpoint(ip):
    """Relance le service disscreen via SSH (préféré) ou pkill+nohup en fallback."""
    user = SSH_PASS_USER
    script = f"/home/{user}/kioske/endpoint.py"
    log = f"/home/{user}/endpoint.log"
    inner = (
        f"systemctl restart disscreen 2>/dev/null || "
        f"(pkill -f 'endpoint.py' 2>/dev/null; "
        f"nohup python3 {shlex.quote(script)} > {shlex.quote(log)} 2>&1 &)"
    )
    result = ssh_run(ip, sudop(inner))
    # Avec '&', le shell renvoie 0 même si pkill n'a rien tué — on accepte donc 0 strictement.
    if result['returncode'] == 0:
        return jsonify({"status": "success", "message": "Commande de relance envoyée"})
    return jsonify({"status": "error",
                    "message": result['stderr'] or result['stdout'] or "Erreur SSH inconnue"}), 500

# ─────────────────────────────────────────────
# SSH HELPERS
# ─────────────────────────────────────────────

def init_ssh_key():
    global MASTER_PUBKEY
    os.makedirs(os.path.dirname(SSH_KEY_PATH), exist_ok=True)
    if not os.path.exists(SSH_KEY_PATH):
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "disscreen-master", "-f", SSH_KEY_PATH],
            check=True, capture_output=True
        )
        print(f"Clé SSH Master générée : {SSH_KEY_PATH}")
    with open(SSH_KEY_PATH + ".pub") as f:
        MASTER_PUBKEY = f.read().strip()

def _ssh_opts_key(timeout):
    return ["-o", "StrictHostKeyChecking=no", "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=yes", "-i", SSH_KEY_PATH]

def _ssh_opts_pass(timeout):
    return ["-o", "StrictHostKeyChecking=no", "-o", f"ConnectTimeout={timeout}",
            "-o", "PasswordAuthentication=yes", "-o", "BatchMode=no"]

def sudop(cmd):
    """Wrapper sudo non-interactif : pipe le mot de passe via stdin (-S)."""
    # On évite le shell ici en utilisant une chaîne qui sera exécutée par l'endpoint
    # mais on s'assure que SSH_PASS est protégé.
    return f"echo {shlex.quote(SSH_PASS)} | sudo -S {cmd} 2>&1"

def ssh_run(ip, command, timeout=15):
    """Connexion SSH : essaie la clé disscreen, puis sshpass en fallback."""
    # 1. Clé SSH (si install.sh a été exécuté sur l'endpoint)
    if os.path.exists(SSH_KEY_PATH):
        try:
            r = subprocess.run(
                ["ssh"] + _ssh_opts_key(timeout) + [f"{SSH_KEY_USER}@{ip}", command],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if r.returncode == 0:
                return {"stdout": r.stdout, "stderr": r.stderr, "returncode": 0}
        except Exception:
            pass

    # 2. Fallback : sshpass avec les credentials du .env
    sshpass_bin = shutil.which("sshpass")
    if not sshpass_bin:
        return {"stdout": "", "stderr": "sshpass non installé. Lancez : sudo apt install sshpass", "returncode": -1}
    try:
        r = subprocess.run(
            [sshpass_bin, "-p", SSH_PASS, "ssh"] + _ssh_opts_pass(timeout) + [f"{SSH_PASS_USER}@{ip}", command],
            capture_output=True, text=True, timeout=timeout + 5
        )
        return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout : impossible de joindre l'endpoint.", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}

def scp_run(ip, local_path, remote_path, timeout=30):
    """SCP vers un endpoint (clé ou sshpass)."""
    if os.path.exists(SSH_KEY_PATH):
        try:
            r = subprocess.run(
                ["scp"] + _ssh_opts_key(timeout) + [local_path, f"{SSH_KEY_USER}@{ip}:{remote_path}"],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if r.returncode == 0:
                return r
        except Exception:
            pass
    sshpass_bin = shutil.which("sshpass")
    if sshpass_bin:
        r = subprocess.run(
            [sshpass_bin, "-p", SSH_PASS, "scp"] + _ssh_opts_pass(timeout) +
            [local_path, f"{SSH_PASS_USER}@{ip}:{remote_path}"],
            capture_output=True, text=True, timeout=timeout + 5
        )
        return r
    raise RuntimeError("Ni clé SSH ni sshpass disponible.")

# ─────────────────────────────────────────────
# MEDIA HELPERS
# ─────────────────────────────────────────────

def get_media_list():
    """Retourne la structure {folders:[...], files:{folder:[{name,type,path}]}}."""
    result = {"folders": [], "files": {"": []}}
    if not os.path.exists(MEDIA_FOLDER):
        return result
    for item in sorted(os.listdir(MEDIA_FOLDER)):
        if item.startswith('.') or item == '__pycache__':
            continue
        full = os.path.join(MEDIA_FOLDER, item)
        if os.path.isdir(full):
            result["folders"].append(item)
            result["files"][item] = []
            for f in sorted(os.listdir(full)):
                if f.startswith('.'): continue
                ext = f.lower().rsplit('.', 1)[-1] if '.' in f else ''
                mtype = ALLOWED_EXT.get(ext)
                if mtype:
                    result["files"][item].append({"name": f, "type": mtype, "path": f"{item}/{f}", "folder": item})
        else:
            ext = item.lower().rsplit('.', 1)[-1] if '.' in item else ''
            mtype = ALLOWED_EXT.get(ext)
            if mtype:
                result["files"][""].append({"name": item, "type": mtype, "path": item, "folder": ""})
    return result

# ─────────────────────────────────────────────
# ROUTES PRINCIPALES
# ─────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html', media=get_media_list())

@app.route('/download_client')
@login_required
def download_client():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'install.sh', as_attachment=True)

@app.route('/player/<ip>')
def player(ip):
    conf = fleet["configs"].get(ip, {"timer": 10, "playlist": []})
    return render_template('player.html', player_config=conf, player_ip=ip)

# ─────────────────────────────────────────────
# ROUTES MEDIA
# ─────────────────────────────────────────────

@app.route('/api/media/create-folder', methods=['POST'])
@login_required
def create_folder():
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({"status": "error", "message": "Nom manquant"}), 400
    
    path = os.path.join(MEDIA_FOLDER, secure_filename(name))
    try:
        os.makedirs(path, exist_ok=True)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    files = request.files.getlist('file')
    folder = request.form.get('folder', '').strip()
    if not files:
        return jsonify({"status": "error"}), 400

    if folder:
        folder = secure_filename(folder)
        target_dir = os.path.join(MEDIA_FOLDER, folder)
        os.makedirs(target_dir, exist_ok=True)
    else:
        target_dir = MEDIA_FOLDER

    for file in files:
        fname = secure_filename(file.filename)
        ext = fname.lower().rsplit('.', 1)[-1] if '.' in fname else ''
        if ext not in ALLOWED_EXT and ext not in ['ppt', 'pptx']:
            continue # skip invalid files

        path = os.path.join(target_dir, fname)
        file.save(path)
        if fname.lower().endswith(('.ppt', '.pptx')):
            try:
                # Conversion PPT -> PDF
                env = os.environ.copy()
                env['HOME'] = '/tmp'
                subprocess.run(['libreoffice', '--headless', '--convert-to', 'pdf',
                                path, '--outdir', target_dir], check=True, timeout=60, env=env)
                os.remove(path)
            except Exception as e:
                print(f"Erreur conversion LibreOffice: {e}")
    
    return jsonify({"status": "success", "media": get_media_list()})

@app.route('/delete/<path:filepath>', methods=['POST'])
@login_required
def delete_file(filepath):
    path = _safe_media_path(filepath)
    if not path:
        return jsonify({"status": "error", "message": "Chemin invalide"}), 400
    if os.path.exists(path) and os.path.isfile(path):
        os.remove(path)
        for ip in fleet["configs"]:
            pl = fleet["configs"][ip]["playlist"]
            if filepath in pl:
                pl.remove(filepath)
                if ip in fleet["active"]:
                    player_sid = fleet["active"][ip].get("player_sid", "")
                    if player_sid:
                        socketio.emit('reload_player', fleet["configs"][ip], room=player_sid)
        socketio.emit('update_ui', fleet)
        return jsonify({"status": "success", "media": get_media_list()})
    return jsonify({"status": "error"}), 404

@app.route('/media/<path:filename>')
def serve_media(filename):
    return send_from_directory(MEDIA_FOLDER, filename)

_SIMPLE_PAGE = (
    '<!DOCTYPE html><html><head><meta charset="UTF-8">'
    '<style>*{{margin:0;padding:0;box-sizing:border-box}}'
    'body{{background:#000;overflow:hidden;width:100vw;height:100vh;'
    'display:flex;align-items:center;justify-content:center}}</style>'
    '</head><body>{body}</body></html>'
)

@app.route('/quickplay/<path:filepath>')
def quickplay(filepath):
    """Page plein-écran kiosk : diaporama PDF (PDF.js) ou image/vidéo."""
    if not _safe_media_path(filepath):
        return "Forbidden", 403
    ext = filepath.lower().rsplit('.', 1)[-1] if '.' in filepath else ''
    mtype = ALLOWED_EXT.get(ext)
    media_url = f"/media/{filepath}"
    try:
        timer_s = max(1, int(request.args.get('timer', 5)))
    except (TypeError, ValueError):
        timer_s = 5

    if mtype == 'image':
        return _SIMPLE_PAGE.format(body=
            f'<img src="{media_url}" style="max-width:100vw;max-height:100vh;object-fit:contain;">')

    if mtype == 'video':
        return _SIMPLE_PAGE.format(body=
            f'<video src="{media_url}" autoplay loop '
            f'style="max-width:100vw;max-height:100vh;object-fit:contain;"></video>')

    if mtype == 'document':
        # Diaporama PDF.js — chaque slide avance automatiquement toutes les timer_s secondes
        timer_ms = timer_s * 1000
        return f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#000;overflow:hidden;width:100vw;height:100vh;
      display:flex;align-items:center;justify-content:center}}
canvas{{display:block}}
#ctr{{position:fixed;bottom:18px;right:22px;color:rgba(255,255,255,.2);
      font:700 11px/1 monospace;letter-spacing:.15em}}
#bar{{position:fixed;bottom:0;left:0;height:3px;background:rgba(255,255,255,.25)}}
</style>
</head><body>
<canvas id="cv"></canvas>
<div id="ctr"></div>
<div id="bar"></div>
<script src="/static/pdfjs/pdf.min.js"></script>
<script>
pdfjsLib.GlobalWorkerOptions.workerSrc='/static/pdfjs/pdf.worker.min.js';
const SRC='{media_url}',DUR={timer_ms};
let pdf,cur=1,tot=0,ti;
async function init(){{
  pdf=await pdfjsLib.getDocument(SRC).promise;
  tot=pdf.numPages;
  await show(1);
  ti=setInterval(next,DUR);
}}
async function show(n){{
  const pg=await pdf.getPage(n);
  const cv=document.getElementById('cv');
  const v0=pg.getViewport({{scale:1}});
  const sc=Math.min(innerWidth/v0.width,innerHeight/v0.height);
  const vp=pg.getViewport({{scale:sc}});
  cv.width=vp.width;cv.height=vp.height;
  await pg.render({{canvasContext:cv.getContext('2d'),viewport:vp}}).promise;
  document.getElementById('ctr').textContent=n+' / '+tot;
  const b=document.getElementById('bar');
  b.style.transition='none';b.style.width='0%';
  requestAnimationFrame(()=>{{b.style.transition='width '+DUR+'ms linear';b.style.width='100%'}});
}}
function next(){{cur=cur>=tot?1:cur+1;show(cur);}}
document.addEventListener('click',()=>{{next();clearInterval(ti);ti=setInterval(next,DUR);}});
init();
</script>
</body></html>'''

    return f"Type non supporté : {ext}", 415

# ─────────────────────────────────────────────
# ROUTES DOSSIERS
# ─────────────────────────────────────────────

@app.route('/api/folders/<old_name>/rename', methods=['POST'])
@login_required
def rename_folder(old_name):
    new_name = request.json.get('new_name', '').strip()
    if not new_name:
        return jsonify({"status": "error", "message": "Nom invalide"}), 400
    
    old_path = os.path.join(MEDIA_FOLDER, secure_filename(old_name))
    new_path = os.path.join(MEDIA_FOLDER, secure_filename(new_name))
    
    if os.path.exists(new_path):
        return jsonify({"status": "error", "message": "Ce nom existe déjà"}), 400
        
    try:
        os.rename(old_path, new_path)
        # Update playlists
        for ip in fleet["configs"]:
            pl = fleet["configs"][ip]["playlist"]
            fleet["configs"][ip]["playlist"] = [p.replace(old_name + "/", new_name + "/") for p in pl]
        save_fleet()
        socketio.emit('update_ui', fleet)
        return jsonify({"status": "success", "media": get_media_list()})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/media/rename', methods=['POST'])
@login_required
def rename_file():
    data = request.json or {}
    old_path_rel = data.get('old_path') or ''
    new_name = data.get('new_name') or ''
    if not old_path_rel or not new_name:
        return jsonify({"status": "error", "message": "Champs manquants"}), 400

    old_full_path = _safe_media_path(old_path_rel)
    if not old_full_path or not os.path.isfile(old_full_path):
        return jsonify({"status": "error", "message": "Fichier introuvable"}), 404

    dir_name = os.path.dirname(old_full_path)
    ext = old_path_rel.rsplit('.', 1)[-1] if '.' in old_path_rel else ''
    new_fname = secure_filename(new_name)
    if not new_fname:
        return jsonify({"status": "error", "message": "Nom invalide"}), 400
    if ext and not new_fname.lower().endswith('.' + ext.lower()):
        new_fname += '.' + ext

    new_full_path = _safe_media_path(os.path.join(os.path.dirname(old_path_rel), new_fname))
    if not new_full_path:
        return jsonify({"status": "error", "message": "Chemin invalide"}), 400
    new_path_rel = os.path.relpath(new_full_path, os.path.realpath(MEDIA_FOLDER))

    if os.path.exists(new_full_path):
        return jsonify({"status": "error", "message": "Fichier existe déjà"}), 400

    try:
        os.rename(old_full_path, new_full_path)
        # Update playlists
        for ip in fleet["configs"]:
            pl = fleet["configs"][ip]["playlist"]
            fleet["configs"][ip]["playlist"] = [p if p != old_path_rel else new_path_rel for p in pl]
        save_fleet()
        socketio.emit('update_ui', fleet)
        return jsonify({"status": "success", "media": get_media_list()})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
@app.route('/api/folders/<name>', methods=['DELETE'])
@login_required
def delete_folder(name):
    safe = secure_filename(name)
    path = os.path.join(MEDIA_FOLDER, safe)
    if os.path.exists(path) and os.path.isdir(path):
        shutil.rmtree(path)
        # Nettoyer les playlists
        for ip in fleet["configs"]:
            pl = fleet["configs"][ip]["playlist"]
            fleet["configs"][ip]["playlist"] = [p for p in pl if not p.startswith(name + "/")]
        save_fleet()
        socketio.emit('update_ui', fleet)
        return jsonify({"status": "success", "media": get_media_list()})
    return jsonify({"status": "error"}), 404

# ─────────────────────────────────────────────
# API SSH DISTANTE
# ─────────────────────────────────────────────

@app.route('/api/master-pubkey')
def master_pubkey():
    return MASTER_PUBKEY, 200, {'Content-Type': 'text/plain'}

@app.route('/api/endpoint/<ip>/restart', methods=['POST'])
@login_required
def restart_endpoint(ip):
    result = ssh_run(ip, sudop("systemctl restart disscreen"))
    if result['returncode'] == 0:
        return jsonify({"status": "success", "message": "Service redémarré."})
    return jsonify({"status": "error", "message": result['stderr'] or result['stdout']}), 500

@app.route('/api/endpoint/<ip>/logs')
@login_required
def get_logs(ip):
    # Essai sans sudo (journal group), sinon avec sudo
    result = ssh_run(ip, f"journalctl -u disscreen -n 80 --no-pager --output=short 2>/dev/null || {sudop('journalctl -u disscreen -n 80 --no-pager --output=short')}")
    if result['returncode'] == 0:
        return jsonify({"status": "success", "logs": result['stdout'] or "(aucun log)"})
    return jsonify({"status": "error", "logs": result['stderr'] or "Impossible de récupérer les logs."}), 500

# ─── Commandes SSH réutilisables ───────────────

# Résolution dynamique de XAUTHORITY pour les commandes X11 via SSH
# On cherche l'utilisateur qui a une session X11 active
_XA_RESOLVE = (
    "U=$(who | grep '(:0)' | cut -d' ' -f1 | head -n1); "
    "U=${U:-YOUR_SESSION_USER}; "
    "XA=/home/$U/.Xauthority; "
    "[ -f $XA ] || XA=$(ls /home/*/.Xauthority 2>/dev/null | head -1); "
)

def _cmd_fullscreen(ip):
    """Tue les barres système puis relance Chromium en kiosk plein écran.
    Tuer le panel seul ne suffit pas : les X11 struts contraignent la fenêtre Chromium
    existante. Il faut donc relancer Chromium après avoir supprimé les panels."""
    player_url = f"http://{MASTER_IP}:5002/player/{ip}"
    return (
        _XA_RESOLVE +
        # Tuer les barres de tâches
        "pkill -9 lxpanel 2>/dev/null; pkill -9 tint2 2>/dev/null; "
        "pkill -9 xfce4-panel 2>/dev/null; pkill -9 gnome-panel 2>/dev/null; "
        "pkill -9 waybar 2>/dev/null; pkill -9 polybar 2>/dev/null; "
        # Tuer Chromium existant et attendre
        "pkill -9 chromium 2>/dev/null; sleep 2; "
        # Relancer Chromium en kiosk avec XAUTHORITY correct
        f"DISPLAY=:0 XAUTHORITY=$XA nohup chromium-browser --kiosk --start-fullscreen "
        f"--noerrdialogs --disable-infobars --no-first-run --simulate-outdated-no-au "
        f"--disable-session-crashed-bubble {player_url} "
        f">/dev/null 2>&1 &"
    )

def _cmd_nowake():
    """Désactive veille/DPMS (xset) + gsettings GNOME + luminosité max."""
    return (
        _XA_RESOLVE +
        # X11 DPMS
        "DISPLAY=:0 XAUTHORITY=$XA xset s off 2>/dev/null; "
        "DISPLAY=:0 XAUTHORITY=$XA xset -dpms 2>/dev/null; "
        "DISPLAY=:0 XAUTHORITY=$XA xset s noblank 2>/dev/null; "
        # GNOME gsettings via D-Bus session de l'utilisateur
        "UID_N=$(id -u); DBUS=unix:path=/run/user/$UID_N/bus; "
        "DBUS_SESSION_BUS_ADDRESS=$DBUS gsettings set org.gnome.desktop.session idle-delay 0 2>/dev/null; "
        "DBUS_SESSION_BUS_ADDRESS=$DBUS gsettings set org.gnome.settings-daemon.plugins.power idle-dim false 2>/dev/null; "
        "DBUS_SESSION_BUS_ADDRESS=$DBUS gsettings set org.gnome.settings-daemon.plugins.power ambient-enabled false 2>/dev/null; "
        "DBUS_SESSION_BUS_ADDRESS=$DBUS gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type \"'nothing'\" 2>/dev/null; "
        "DBUS_SESSION_BUS_ADDRESS=$DBUS gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type \"'nothing'\" 2>/dev/null; "
        "DBUS_SESSION_BUS_ADDRESS=$DBUS gsettings set org.gnome.desktop.screensaver lock-enabled false 2>/dev/null; "
        # Luminosité
        "brightnessctl set 100% 2>/dev/null; "
        "true"
    )

@app.route('/api/endpoint/<ip>/fullscreen', methods=['POST'])
@login_required
def force_fullscreen(ip):
    r = ssh_run(ip, _cmd_fullscreen(ip))
    return jsonify({"status": "success" if r['returncode'] == 0 else "error",
                    "message": "Plein écran forcé." if r['returncode'] == 0 else r['stderr']})

@app.route('/api/endpoint/<ip>/nowake', methods=['POST'])
@login_required
def force_nowake(ip):
    r = ssh_run(ip, _cmd_nowake())
    return jsonify({"status": "success" if r['returncode'] == 0 else "error",
                    "message": "Veille désactivée." if r['returncode'] == 0 else r['stderr']})

@app.route('/api/fleet/fullscreen', methods=['POST'])
@login_required
def fleet_fullscreen():
    results = {}
    for ip in list(fleet["active"].keys()):
        r = ssh_run(ip, _cmd_fullscreen(ip))
        results[ip] = {"status": "success" if r['returncode'] == 0 else "error"}
    return jsonify({"status": "success", "results": results})

@app.route('/api/fleet/nowake', methods=['POST'])
@login_required
def fleet_nowake():
    results = {}
    for ip in list(fleet["active"].keys()):
        r = ssh_run(ip, _cmd_nowake())
        results[ip] = {"status": "success" if r['returncode'] == 0 else "error"}
    return jsonify({"status": "success", "results": results})

@app.route('/api/endpoint/<ip>/screen', methods=['POST'])
@login_required
def screen_power(ip):
    """Allume ou éteint l'écran via xset dpms."""
    action = request.json.get('action', 'on')
    if action == 'off':
        cmd = _XA_RESOLVE + "DISPLAY=:0 XAUTHORITY=$XA xset dpms force off"
    else:
        cmd = _XA_RESOLVE + "DISPLAY=:0 XAUTHORITY=$XA xset dpms force on && DISPLAY=:0 XAUTHORITY=$XA xset s reset"
    result = ssh_run(ip, cmd)
    return jsonify({"status": "success" if result['returncode'] == 0 else "error",
                    "message": result['stderr'] or result['stdout']})

@app.route('/api/endpoint/<ip>/update', methods=['POST'])
@login_required
def update_endpoint(ip):
    """Déploie endpoint.py au chemin standard + redémarre le service."""
    script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'endpoint', 'endpoint.py')
    if not os.path.exists(script_path):
        return jsonify({"status": "error", "message": "endpoint.py introuvable"}), 404
    try:
        r = scp_run(ip, script_path, "/tmp/endpoint_new.py")
        if r.returncode != 0:
            return jsonify({"status": "error", "message": f"SCP échoué : {r.stderr.strip()}"}), 500

        user = SSH_PASS_USER
        dest = f"/home/{user}/kioske/endpoint.py"
        # Conf master_ip : on encode en base64 pour éviter tout problème de quoting.
        conf_b64 = _b64.b64encode(f"MASTER_IP={MASTER_IP}\n".encode()).decode()
        conf_path = f"/home/{user}/.disscreen_master"
        fix_cmd = (
            f"{sudop(f'mkdir -p /home/{user}/kioske && cp /tmp/endpoint_new.py {dest} && chown -R {user}:{user} /home/{user}/kioske')} ; "
            f"echo '{conf_b64}' | base64 -d | {sudop(f'tee {conf_path} > /dev/null')} ; "
            f"{sudop(f'chown {user}:{user} {conf_path}')} ; "
            "pkill -9 lxpanel 2>/dev/null ; pkill -9 tint2 2>/dev/null ; "
            "pkill -9 xfce4-panel 2>/dev/null ; pkill -9 gnome-panel 2>/dev/null ; true ; "
            f"{sudop('systemctl restart disscreen')}"
        )
        result = ssh_run(ip, fix_cmd, timeout=30)
        if result['returncode'] == 0:
            return jsonify({"status": "success",
                            "message": "Script mis à jour et service redémarré."})
        return jsonify({"status": "error", "message": result['stderr'] or result['stdout']}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ─────────────────────────────────────────────
# DÉPLOIEMENT FLEET
# ─────────────────────────────────────────────

@app.route('/api/fleet/deploy', methods=['POST'])
@login_required
def fleet_deploy():
    """Déploie endpoint.py sur toute la flotte active via SCP + restart."""
    script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'endpoint', 'endpoint.py')
    if not os.path.exists(script_path):
        return jsonify({"status": "error", "message": "endpoint.py introuvable"}), 404

    results = {}
    for ip in list(fleet["active"].keys()):
        try:
            r = scp_run(ip, script_path, "/tmp/endpoint_new.py")
            if r.returncode != 0:
                results[ip] = {"status": "error", "message": r.stderr.strip()}
                continue
            deploy = ssh_run(ip, f"{sudop(f'mkdir -p /home/{SSH_PASS_USER}/kioske && cp /tmp/endpoint_new.py /home/{SSH_PASS_USER}/kioske/endpoint.py')} && {sudop('systemctl restart disscreen')}")
            results[ip] = {
                "status": "success" if deploy['returncode'] == 0 else "error",
                "message": "Déployé et redémarré" if deploy['returncode'] == 0 else deploy['stderr'].strip()
            }
        except Exception as e:
            results[ip] = {"status": "error", "message": str(e)}

    return jsonify({"status": "success", "results": results})

# ─────────────────────────────────────────────
# BROADCAST FLEET
# ─────────────────────────────────────────────

@app.route('/api/fleet/broadcast', methods=['POST'])
@login_required
def fleet_broadcast():
    """Envoie un fichier sur tous les endpoints actifs en ligne d'un coup."""
    filepath = (request.json or {}).get('filepath', '').strip()
    if not filepath or not _safe_media_path(filepath):
        return jsonify({"status": "error", "message": "Chemin invalide"}), 400
    sent = 0
    host = (request.host or f"{MASTER_IP}:5002").split(':')[0]
    for ip, node in fleet["active"].items():
        if node.get("status") == "online":
            sid = node.get("sid", "")
            if sid:
                timer = fleet["configs"].get(ip, {}).get("timer", 5)
                url = f"http://{host}:5002/quickplay/{filepath}?timer={timer}"
                socketio.emit('remote_authorize', {"url": url}, room=sid)
                sent += 1
    return jsonify({"status": "success", "sent": sent})

# ─────────────────────────────────────────────
# PROVISIONING NOUVEL ENDPOINT
# ─────────────────────────────────────────────

@app.route('/api/endpoint/test-ssh', methods=['POST'])
@login_required
def test_ssh_endpoint():
    """Teste la connexion SSH vers un endpoint candidat."""
    data = request.json or {}
    ip       = data.get('ip', '').strip()
    user     = data.get('user', 'YOUR_SESSION_USER').strip()
    password = data.get('password', '').strip()
    if not all([ip, user, password]):
        return jsonify({"status": "error", "message": "Champs manquants"}), 400
    sshpass_bin = shutil.which("sshpass")
    if not sshpass_bin:
        return jsonify({"status": "error", "message": "sshpass non installé sur le master"}), 500
    try:
        r = subprocess.run(
            [sshpass_bin, "-p", password, "ssh",
             "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8",
             "-o", "PasswordAuthentication=yes", "-o", "BatchMode=no",
             f"{user}@{ip}", "hostname && lsb_release -ds 2>/dev/null || uname -r"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0:
            lines = [l.strip() for l in r.stdout.strip().split('\n') if l.strip()]
            hostname = lines[0] if lines else ip
            sysinfo  = lines[1] if len(lines) > 1 else ''
            return jsonify({"status": "success", "hostname": hostname, "sysinfo": sysinfo})
        return jsonify({"status": "error",
                        "message": (r.stderr or r.stdout or "Connexion refusée").strip()[:300]})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Timeout — hôte inaccessible ou SSH fermé"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/endpoint/provision', methods=['POST'])
@login_required
def provision_endpoint():
    """Installe disscreen sur un nouvel endpoint via SSH et émet la progression via SocketIO."""
    data     = request.json or {}
    ip       = data.get('ip', '').strip()
    user     = data.get('user', 'YOUR_SESSION_USER').strip()
    password = data.get('password', '').strip()
    browser_sid = data.get('sid', '')
    if not all([ip, user, password]):
        return jsonify({"status": "error", "message": "Paramètres manquants"}), 400
    sshpass_bin = shutil.which("sshpass")
    if not sshpass_bin:
        return jsonify({"status": "error", "message": "sshpass non installé"}), 500

    script_local = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'endpoint', 'endpoint.py')

    def do_provision():
        def emit_p(msg, status='info'):
            socketio.emit('provision_progress', {'msg': msg, 'status': status},
                          room=browser_sid)

        def ssh_p(cmd, timeout=90):
            return subprocess.run(
                [sshpass_bin, "-p", password, "ssh",
                 "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                 "-o", "PasswordAuthentication=yes", "-o", "BatchMode=no",
                 f"{user}@{ip}", cmd],
                capture_output=True, text=True, timeout=timeout
            )

        def scp_p(local, remote, timeout=30):
            return subprocess.run(
                [sshpass_bin, "-p", password, "scp",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "PasswordAuthentication=yes", "-o", "BatchMode=no",
                 local, f"{user}@{ip}:{remote}"],
                capture_output=True, text=True, timeout=timeout
            )

        pw_q = shlex.quote(password)
        sudo_p = f"echo {pw_q} | sudo -S"

        try:
            eventlet.sleep(0)

            # 0. Sanity check : sudo non-interactif fonctionne ?
            emit_p("🔐 Vérification sudo...")
            r = ssh_p(f"{sudo_p} -n true 2>&1 || {sudo_p} true 2>&1")
            if r.returncode != 0:
                emit_p(f"❌ sudo impossible avec ce mot de passe : {(r.stderr or r.stdout).strip()[:200]}", 'error')
                return
            emit_p("✅ Sudo OK")
            eventlet.sleep(0)

            # 1. Détection de la distro et nom du paquet chromium
            emit_p("🔍 Détection de la distribution...")
            r = ssh_p(". /etc/os-release 2>/dev/null && echo $ID:$VERSION_CODENAME")
            distro = (r.stdout or '').strip() or 'unknown'
            emit_p(f"📋 Distribution : {distro}")
            eventlet.sleep(0)

            # 2. Dépendances système (essaie chromium puis chromium-browser)
            emit_p("📦 Mise à jour apt + installation des dépendances (peut prendre 2-3min)...")
            r = ssh_p(
                f"{sudo_p} apt-get update -qq 2>&1 | tail -2 && "
                f"({sudo_p} DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "chromium python3-pip x11-xserver-utils xdotool wmctrl unclutter brightnessctl 2>&1 || "
                f"{sudo_p} DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "chromium-browser python3-pip x11-xserver-utils xdotool wmctrl unclutter brightnessctl 2>&1) "
                "| tail -5",
                timeout=300
            )
            eventlet.sleep(0)
            emit_p("✅ Dépendances système OK" if r.returncode == 0
                   else f"⚠️  apt partiel — vérifie les logs ({r.stdout.strip()[-120:]})")

            # 3. Vérifier qu'un binaire chromium est joignable
            r = ssh_p("command -v chromium || command -v chromium-browser || command -v /snap/bin/chromium")
            chromium_bin = r.stdout.strip() if r.returncode == 0 else ''
            if chromium_bin:
                emit_p(f"✅ Chromium détecté : {chromium_bin}")
            else:
                emit_p("⚠️  Aucun binaire chromium trouvé — le kiosque ne pourra pas afficher.", 'error')
            eventlet.sleep(0)

            # 4. Python packages
            emit_p("🐍 Installation python-socketio...")
            r = ssh_p(
                "pip3 install 'python-socketio[client]' requests "
                "--break-system-packages -q 2>&1 | tail -2",
                timeout=120
            )
            eventlet.sleep(0)
            emit_p("✅ python-socketio OK" if r.returncode == 0 else f"⚠️  pip partiel : {r.stdout.strip()[-120:]}")

            # 5. UID de l'utilisateur
            r = ssh_p(f"id -u {shlex.quote(user)}")
            uid = r.stdout.strip() if r.returncode == 0 and r.stdout.strip().isdigit() else "1000"

            # 6. Copie du script (on évite /tmp à cause des permissions sticky bit)
            emit_p("📋 Copie du script endpoint...")
            staging = f"/home/{user}/.endpoint_new.py"
            r = scp_p(script_local, staging)
            if r.returncode != 0:
                emit_p(f"❌ SCP échoué : {r.stderr[:200]}", 'error'); return
            eventlet.sleep(0)

            dest_dir    = f"/home/{user}/kioske"
            dest_script = f"{dest_dir}/endpoint.py"
            r = ssh_p(
                f"mkdir -p {dest_dir} && cp {staging} {dest_script} && "
                f"rm -f {staging} && chmod 755 {dest_script}"
            )
            if r.returncode != 0:
                emit_p(f"❌ Copie échouée : {r.stderr[:200]}", 'error'); return
            emit_p("✅ Script déployé")
            eventlet.sleep(0)

            # 7. Écriture de la conf master_ip (consommée par endpoint.py au boot)
            conf_b64 = _b64.b64encode(f"MASTER_IP={MASTER_IP}\n".encode()).decode()
            conf_path = f"/home/{user}/.disscreen_master"
            ssh_p(f"echo '{conf_b64}' | base64 -d > {conf_path} && chmod 644 {conf_path}")
            eventlet.sleep(0)

            # 5. Service systemd (encodé en base64 pour éviter les problèmes de quoting)
            emit_p("⚙️  Création du service systemd...")
            svc = (
                "[Unit]\nDescription=ScreenManager Endpoint Client\n"
                "After=network.target graphical-session.target display-manager.service\n"
                "Wants=graphical.target\n\n"
                "[Service]\n"
                f'ExecStartPre=/bin/bash -c "i=0; while [ $i -lt 30 ]; do '
                f'[ -f /home/{user}/.Xauthority ] && break; '
                f'[ -S /run/user/{uid}/wayland-0 ] && break; '
                f'i=$((i+1)); sleep 2; done"\n'
                f"ExecStart=/usr/bin/python3 {dest_script}\n"
                "Restart=always\nRestartSec=10\nUser=root\n"
                "Environment=DISPLAY=:0\n"
                f"Environment=XAUTHORITY=/home/{user}/.Xauthority\n"
                "Environment=WAYLAND_DISPLAY=wayland-0\n"
                f"Environment=XDG_RUNTIME_DIR=/run/user/{uid}\n"
                f"Environment=MASTER_IP={MASTER_IP}\n\n"
                "[Install]\nWantedBy=graphical.target\n"
            )
            svc_b64 = _b64.b64encode(svc.encode()).decode()
            r = ssh_p(
                f"echo '{svc_b64}' | base64 -d | {sudo_p} tee "
                "/etc/systemd/system/disscreen.service > /dev/null 2>&1"
            )
            if r.returncode != 0:
                emit_p(f"❌ Service échoué : {r.stderr[:200]}", 'error'); return
            eventlet.sleep(0)

            # 6. Auto-login GDM (si gdm3 présent)
            emit_p("🖥️  Configuration auto-login...")
            gdm = (
                "[daemon]\nAutomaticLoginEnable=true\n"
                f"AutomaticLogin={user}\nWaylandEnable=false\n\n"
                "[security]\n\n[xdmcp]\n\n[chooser]\n\n[debug]\n"
            )
            gdm_b64 = _b64.b64encode(gdm.encode()).decode()
            ssh_p(
                f"[ -f /etc/gdm3/custom.conf ] && "
                f"echo '{gdm_b64}' | base64 -d | {sudo_p} tee "
                "/etc/gdm3/custom.conf > /dev/null 2>&1 || true"
            )
            eventlet.sleep(0)

            # 7. Masquer veille système
            ssh_p(
                f"{sudo_p} systemctl mask sleep.target suspend.target "
                "hibernate.target hybrid-sleep.target 2>/dev/null || true"
            )

            # 8. Nettoyage : tuer tout endpoint.py orphelin (legacy)
            emit_p("🧹 Nettoyage des anciens process...")
            ssh_p(
                f"{sudo_p} pkill -9 -f legacy-kioske 2>/dev/null; "
                f"{sudo_p} pkill -9 -f /home/{user}/endpoint.py 2>/dev/null; "
                "true"
            )
            eventlet.sleep(0)

            # 9. Démarrage du service
            emit_p("🚀 Activation et démarrage du service disscreen...")
            r = ssh_p(
                f"{sudo_p} systemctl daemon-reload && "
                f"{sudo_p} systemctl enable disscreen.service && "
                f"{sudo_p} systemctl restart disscreen.service",
                timeout=30
            )
            eventlet.sleep(0)
            if r.returncode != 0:
                emit_p(f"❌ Démarrage échoué : {r.stderr[:200]}", 'error'); return

            # 10. Vérification finale : le service est-il actif ?
            eventlet.sleep(2)
            r = ssh_p(f"{sudo_p} systemctl is-active disscreen.service")
            state = (r.stdout or '').strip()
            if state != 'active':
                logs = ssh_p(f"{sudo_p} journalctl -u disscreen -n 15 --no-pager 2>&1 | tail -10")
                emit_p(f"⚠️  Service état : {state} — derniers logs :\n{(logs.stdout or '')[-400:]}", 'error')
                return

            emit_p("✅ Service disscreen actif")
            emit_p("🎉 Installation terminée ! L'écran va apparaître dans la flotte d'ici quelques secondes.", 'done')

        except subprocess.TimeoutExpired:
            emit_p("❌ Timeout — opération trop longue", 'error')
        except Exception as e:
            emit_p(f"❌ Erreur inattendue : {e}", 'error')

    eventlet.spawn(do_provision)
    return jsonify({"status": "started"})

# ─────────────────────────────────────────────
# SCREEN MAP
# ─────────────────────────────────────────────

def load_screenmap():
    if os.path.exists(SCREENMAP_FILE):
        with open(SCREENMAP_FILE) as f:
            return json.load(f)
    return {"image": None, "markers": []}

def save_screenmap_data(data):
    with open(SCREENMAP_FILE, 'w') as f:
        json.dump(data, f)

@app.route('/api/screenmap')
@login_required
def get_screenmap():
    return jsonify(load_screenmap())

@app.route('/api/screenmap/image', methods=['POST'])
@login_required
def upload_screenmap_image():
    file = request.files.get('file')
    if not file:
        return jsonify({"status": "error"}), 400
    os.makedirs(os.path.join(MEDIA_FOLDER, 'screenmap'), exist_ok=True)
    fname = secure_filename(file.filename)
    path = os.path.join(MEDIA_FOLDER, 'screenmap', fname)
    file.save(path)
    sm = load_screenmap()
    sm["image"] = f"screenmap/{fname}"
    save_screenmap_data(sm)
    return jsonify({"status": "success", "image": sm["image"]})

@app.route('/api/screenmap/markers', methods=['POST'])
@login_required
def save_markers():
    data = request.json
    sm = load_screenmap()
    sm["markers"] = data.get("markers", [])
    save_screenmap_data(sm)
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────
# SOCKET EVENTS
# ─────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    # Nettoyage si le Master s'est auto-enregistré par erreur
    emit('update_ui', fleet)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    for ip in list(fleet["active"].keys()):
        if fleet["active"][ip].get("sid") == sid:
            fleet["active"][ip]["status"] = "offline"
            socketio.emit('update_ui', fleet)
            break
    for ip in list(fleet["pending"].keys()):
        if fleet["pending"][ip].get("sid") == sid:
            del fleet["pending"][ip]
            socketio.emit('update_ui', fleet)
            break

@socketio.on('heartbeat')
def handle_heartbeat(data):
    ip = request.remote_addr
    hostname = data.get("hostname") if data else None
    updated = False
    
    # Essayer de trouver l'endpoint par IP ou par hostname
    for target_ip, node in fleet["active"].items():
        if target_ip == ip or (hostname and node.get("hostname") == hostname):
            fleet["active"][target_ip]["last_seen"] = time.time()
            if fleet["active"][target_ip]["status"] != "online":
                fleet["active"][target_ip]["status"] = "online"
                updated = True
                
    if updated:
        socketio.emit('update_ui', fleet)

@socketio.on('register_request')
def handle_register(data):
    ip = request.remote_addr
    hostname = data.get('hostname', 'Écran')
    active_ip = None
    
    for target_ip, node in fleet["active"].items():
        if target_ip == ip or node.get("hostname") == hostname:
            active_ip = target_ip
            break

    if not active_ip:
        fleet["pending"][ip] = {
            "hostname": hostname,
            "sid": request.sid,
            "custom_name": "",
            "last_seen": time.time(),
            "status": "online"
        }
    else:
        # Reconnexion d'un terminal déjà approuvé
        fleet["active"][active_ip]["sid"] = request.sid
        fleet["active"][active_ip]["last_seen"] = time.time()
        fleet["active"][active_ip]["status"] = "online"
        # Ré-autoriser automatiquement sans intervention manuelle
        player_url = f"http://{request.host.split(':')[0]}:5002/player/{active_ip}"
        emit('remote_authorize', {"url": player_url})
    if ip not in fleet["configs"]:
        fleet["configs"][ip] = {"timer": 10, "playlist": []}
    socketio.emit('update_ui', fleet)
    save_fleet()

@socketio.on('approve_endpoint')
@socket_login_required
def approve(data):
    ip = (data or {}).get('ip')
    if ip and ip in fleet["pending"]:
        node = fleet["pending"].pop(ip)
        node.setdefault("custom_name", "")
        node["last_seen"] = time.time()
        node["status"] = "online"
        fleet["active"][ip] = node
        host = (request.host or f"{MASTER_IP}:5002").split(':')[0]
        player_url = f"http://{host}:5002/player/{ip}"
        socketio.emit('remote_authorize', {"url": player_url}, room=node['sid'])
        socketio.emit('update_ui', fleet)
        save_fleet()

@socketio.on('join_player')
def handle_join_player(data):
    ip = data.get('ip')
    if ip in fleet["active"]:
        fleet["active"][ip]["player_sid"] = request.sid   # SID du navigateur uniquement
        conf = fleet["configs"].get(ip, {"timer": 10, "playlist": []})
        emit('reload_player', conf)

@socketio.on('update_node_config')
@socket_login_required
def update_config(data):
    ip = (data or {}).get('ip')
    if ip and ip in fleet["configs"]:
        try:
            fleet["configs"][ip]["timer"] = max(1, int(data.get('timer', 5)))
        except (TypeError, ValueError):
            fleet["configs"][ip]["timer"] = 5
        playlist = data.get('playlist') or []
        if isinstance(playlist, list):
            fleet["configs"][ip]["playlist"] = [str(p) for p in playlist]
        if ip in fleet["active"]:
            player_sid = fleet["active"][ip].get("player_sid", "")
            if player_sid:
                socketio.emit('reload_player', fleet["configs"][ip], room=player_sid)
        socketio.emit('update_ui', fleet)
        save_fleet()

@app.route('/api/endpoint/<ip>/push', methods=['POST'])
@login_required
def push_media(ip):
    """Envoie un fichier de la médiathèque directement sur un endpoint."""
    filepath = (request.json or {}).get('filepath', '').strip()
    if not filepath or not _safe_media_path(filepath):
        return jsonify({"status": "error", "message": "Chemin invalide"}), 400
    if ip not in fleet["active"]:
        return jsonify({"status": "error", "message": "Terminal non connecté"}), 404
    timer = fleet["configs"].get(ip, {}).get("timer", 5)
    host = (request.host or f"{MASTER_IP}:5002").split(':')[0]
    url = f"http://{host}:5002/quickplay/{filepath}?timer={timer}"
    socketio.emit('remote_authorize', {"url": url}, room=fleet["active"][ip]['sid'])
    return jsonify({"status": "success", "url": url})

@app.route('/api/endpoint/<ip>/screenshot')
@login_required
def endpoint_screenshot(ip):
    if ip not in fleet["active"]:
        return '', 404
    img = get_screenshot(ip)
    if not img:
        return '', 503
    resp = app.make_response(img)
    resp.headers['Content-Type'] = 'image/jpeg'
    resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.route('/api/endpoint/<ip>/rename', methods=['POST'])
@login_required
def rename_endpoint(ip):
    name = (request.json or {}).get('name', '').strip()
    if ip in fleet["active"]:
        fleet["active"][ip]["custom_name"] = name
        socketio.emit('update_ui', fleet)
        save_fleet()
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@socketio.on('force_relaunch_all')
@socket_login_required
def force_relaunch_all():
    """Demande à tous les terminaux actifs de relancer leur mode Kiosque."""
    for node in fleet["active"].values():
        sid = node.get('sid')
        if sid:
            socketio.emit('force_relaunch', room=sid)

@socketio.on('force_relaunch_node')
@socket_login_required
def force_relaunch_node(data):
    """Demande à un terminal spécifique de relancer son mode Kiosque."""
    ip = (data or {}).get('ip')
    if ip and ip in fleet["active"]:
        sid = fleet["active"][ip].get('sid')
        if sid:
            socketio.emit('force_relaunch', room=sid)

@app.route('/api/fleet/relaunch', methods=['POST'])
@login_required
def fleet_relaunch_route():
    """Endpoint HTTP pour relancer (force_relaunch) toute la flotte."""
    sent = 0
    for node in fleet["active"].values():
        sid = node.get('sid')
        if sid:
            socketio.emit('force_relaunch', room=sid)
            sent += 1
    return jsonify({"status": "success", "sent": sent})

def health_check_loop():
    """Marque offline les terminaux sans heartbeat depuis plus de 60s."""
    eventlet.sleep(30)
    while True:
        now = time.time()
        changed = False
        for ip in list(fleet["active"].keys()):
            if fleet["active"][ip]["status"] != "offline":
                if now - fleet["active"][ip].get("last_seen", 0) > 60:
                    fleet["active"][ip]["status"] = "offline"
                    changed = True
        if changed:
            socketio.emit('update_ui', fleet)
        eventlet.sleep(30)

if __name__ == '__main__':
    ensure_pdfjs()
    load_fleet()
    init_ssh_key()
    eventlet.spawn(health_check_loop)
    socketio.run(app, host='0.0.0.0', port=5002)
