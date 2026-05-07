import os
import sys
import shutil
import subprocess
import time
import socket
import base64
import json as _json
import threading

shutil_which = shutil.which

# --- CONFIGURATION ---
def _read_master_ip():
    """Master IP : env var, config file, ou défaut localhost."""
    if os.environ.get('MASTER_IP'):
        return os.environ['MASTER_IP'].strip()
    for path in (os.path.expanduser(os.path.expanduser('~/.disscreen_master')),
                 '/etc/disscreen/master.conf'):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        k, v = line.split('=', 1)
                        if k.strip().upper() == 'MASTER_IP':
                            return v.strip()
                    else:
                        return line
        except (OSError, IOError):
            pass
    return '127.0.0.1'

MASTER_IP = _read_master_ip()
PORT = os.environ.get('MASTER_PORT', '5002')
CDP_PORT = 9222
HEARTBEAT_S = 15
USER_DATA_DIR = '/tmp/chromium-kiosk-main'

_launch_lock = threading.Lock()
_current_url = None

def _get_env():
    """Détecte l'environnement et l'XAUTHORITY."""
    env = os.environ.copy()
    env['DISPLAY'] = env.get('DISPLAY', ':0')
    user = os.environ.get('USER') or 'YOUR_SESSION_USER'
    candidates = [
        os.path.expanduser('~/.Xauthority'),
        f'/home/{user}/.Xauthority',
        '/home/YOUR_SESSION_USER/.Xauthority',
        '/var/run/lightdm/root/:0',
    ]
    for xa in candidates:
        if xa and os.path.exists(xa):
            env['XAUTHORITY'] = xa
            break
    if not env.get('XDG_RUNTIME_DIR'):
        env['XDG_RUNTIME_DIR'] = f'/run/user/{os.getuid()}'
    return env

def _wait_cdp_ready(timeout_s=20):
    """Attend que le port CDP de Chromium réponde avec au moins une page."""
    import urllib.request
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = urllib.request.urlopen(f'http://127.0.0.1:{CDP_PORT}/json/list', timeout=1)
            pages = [t for t in _json.loads(r.read()) if t.get('type') == 'page']
            if pages:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False

def _cdp_navigate(url, retries=3):
    """Navigue l'onglet existant via CDP. Renvoie True si la navigation a été acceptée."""
    import urllib.request
    for attempt in range(retries):
        try:
            r = urllib.request.urlopen(f'http://127.0.0.1:{CDP_PORT}/json/list', timeout=2)
            pages = [t for t in _json.loads(r.read()) if t.get('type') == 'page']
            if not pages:
                time.sleep(0.5)
                continue
            ws_url = pages[0]['webSocketDebuggerUrl']
            path = '/' + ws_url.split('/', 3)[-1]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(('127.0.0.1', CDP_PORT))
            ws_key = base64.b64encode(os.urandom(16)).decode()
            sock.sendall((
                f'GET {path} HTTP/1.1\r\n'
                f'Host: 127.0.0.1:{CDP_PORT}\r\n'
                'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                f'Sec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\n\r\n'
            ).encode())
            # Lire le handshake complet
            handshake = b''
            while b'\r\n\r\n' not in handshake:
                chunk = sock.recv(4096)
                if not chunk:
                    sock.close()
                    raise ConnectionError('handshake closed')
                handshake += chunk
            if b'101' not in handshake.split(b'\r\n', 1)[0]:
                sock.close()
                continue
            # Envoyer Page.navigate
            msg = _json.dumps({'id': 1, 'method': 'Page.navigate',
                               'params': {'url': url}}).encode()
            mask = os.urandom(4)
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(msg))
            n = len(msg)
            if n < 126:
                header = bytes([0x81, 0x80 | n])
            else:
                header = bytes([0x81, 0xFE, n >> 8, n & 0xFF])
            sock.sendall(header + mask + masked)
            # Attendre l'ack pour ne pas couper la nav en plein vol
            try:
                sock.settimeout(2)
                _ = sock.recv(4096)
            except Exception:
                pass
            sock.close()
            return True
        except Exception:
            time.sleep(0.4)
    return False

def _kill_chromium():
    print('🔪 Nettoyage Chromium...')
    for _ in range(5):
        for p in ('chromium', 'chrome'):
            subprocess.run(['pkill', '-9', '-f', p],
                           stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.4)
        r = subprocess.run(['pgrep', '-f', 'chromium'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            break
    # Nettoyer les locks de l'instance kiosk pour qu'un nouveau process
    # ouvre une vraie nouvelle fenêtre kiosk (et pas un onglet dans une
    # instance fantôme).
    for f in ('SingletonLock', 'SingletonCookie', 'SingletonSocket'):
        try:
            os.remove(os.path.join(USER_DATA_DIR, f))
        except OSError:
            pass

def _run_optional(cmd, env, **kw):
    """Lance une commande optionnelle : ignore l'absence du binaire."""
    try:
        return subprocess.run(cmd, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
    except FileNotFoundError:
        return None

def _popen_optional(cmd, env):
    try:
        return subprocess.Popen(cmd, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(f"⚠️  {cmd[0]} non installé — étape ignorée.")
        return None

def setup_kiosk():
    print('🛠️  Config Kiosque...')
    env = _get_env()
    # Openbox n'est nécessaire que sur les setups sans WM (Raspberry minimal etc.)
    # Sur un desktop classique (GNOME, Cinnamon...) il existe déjà un WM : on saute.
    try:
        subprocess.check_output(['pgrep', 'openbox'], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        # Pas d'openbox actif. On essaie de le démarrer s'il est installé,
        # sinon on suppose qu'un autre WM tourne déjà.
        if shutil_which('openbox'):
            print('🪟 Start Openbox')
            _popen_optional(['openbox'], env)
        else:
            print('ℹ️  openbox non installé — on suppose un WM déjà actif.')
    _run_optional(['xset', 's', 'off', '-dpms'], env)
    try:
        subprocess.check_output(['pgrep', 'unclutter'], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        _popen_optional(['unclutter', '-idle', '0.5', '-root'], env)

def _find_chromium():
    """Cherche un binaire chromium utilisable parmi les noms/chemins connus."""
    for name in ('chromium', 'chromium-browser',
                 '/snap/bin/chromium', '/usr/bin/chromium',
                 '/usr/bin/chromium-browser'):
        path = shutil_which(name) or (name if os.path.exists(name) else None)
        if path:
            return path
    return None

def launch_chromium(url):
    """Toujours actualiser la page existante via CDP. Sinon, kill propre + relance kiosk."""
    global _current_url
    with _launch_lock:
        # Si Chromium tourne déjà, naviguer dans l'onglet existant : pas de flash,
        # pas de nouvelle fenêtre par-dessus l'écran d'attente.
        if _cdp_navigate(url):
            print(f'✅ Navigué vers {url}')
            _current_url = url
            _force_fullscreen()
            return

        # Sinon on tue tout et on relance proprement en kiosk.
        _kill_chromium()
        chromium_bin = _find_chromium()
        if not chromium_bin:
            print('❌ Aucun binaire chromium trouvé — installer chromium ou chromium-browser.')
            _current_url = url
            return
        print(f'🎬 Relance Chromium ({chromium_bin}) : {url}')
        env = _get_env()
        cmd = [
            chromium_bin,
            '--kiosk', '--start-fullscreen', '--no-first-run',
            '--noerrdialogs', '--disable-infobars', '--no-sandbox',
            '--disable-features=TranslateUI',
            f'--user-data-dir={USER_DATA_DIR}',
            f'--remote-debugging-port={CDP_PORT}',
            '--autoplay-policy=no-user-gesture-required',
            '--simulate-outdated-no-au',
            '--window-position=0,0',
            '--ozone-platform=x11',
            url,
        ]
        subprocess.Popen(cmd, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _current_url = url
        threading.Thread(target=_post_launch_setup, daemon=True).start()

def _post_launch_setup():
    """Attend que CDP soit prêt, puis martèle le fullscreen quelques fois."""
    _wait_cdp_ready(20)
    for _ in range(8):
        time.sleep(2)
        _force_fullscreen()

def _force_fullscreen():
    env = _get_env()
    _run_optional(['wmctrl', '-a', 'chromium'], env)
    _run_optional(['wmctrl', '-r', 'chromium', '-b', 'add,fullscreen'], env)
    # Attention : F11 peut sortir du kiosk sur certains chromium ; on évite si possible.
    # On se contente de wmctrl pour la mise au premier plan + fullscreen.

def show_wait_screen():
    """Splash kiosk minimaliste : fond clair, logo SVG placeholder, IP, statut."""
    hostname = os.uname()[1]
    # Logo SVG inline (placeholder) : pas de dépendance réseau au master
    # tant que l'endpoint n'est pas connecté.
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>ScreenManager</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{width:100%;height:100%;background:#fbfbfd;color:#0f172a;
  font-family:'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased}}
.wrap{{position:fixed;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;gap:2.2rem;text-align:center}}
.logo{{display:block;max-width:300px;width:60vmin;height:auto}}
.pill{{display:inline-flex;align-items:center;gap:.7rem;
  padding:.55rem 1.2rem;border-radius:999px;background:#fff;
  border:1px solid #e2e8f0;font-size:.78rem;font-weight:600;
  color:#475569;letter-spacing:.06em;
  box-shadow:0 1px 2px rgba(15,23,42,.04)}}
.dot{{width:7px;height:7px;border-radius:50%;background:#4e79e9;
  animation:dotPulse 1.8s ease-in-out infinite}}
@keyframes dotPulse{{
  0%{{box-shadow:0 0 0 0 rgba(78,121,233,.45)}}
  70%{{box-shadow:0 0 0 10px rgba(78,121,233,0)}}
  100%{{box-shadow:0 0 0 0 rgba(78,121,233,0)}}}}
.host{{font-family:'Courier New',monospace;font-size:.72rem;
  color:#94a3b8;letter-spacing:.06em}}
</style></head>
<body>
<div class="wrap">
  <svg class="logo" viewBox="0 0 320 90" xmlns="http://www.w3.org/2000/svg" aria-label="ScreenManager">
    <!-- Replace this SVG with your company logo -->
    <rect x="10" y="10" width="300" height="70" rx="8" fill="none" stroke="#e2e8f0" stroke-width="2"/>
    <text x="160" y="56" text-anchor="middle"
          font-family="Helvetica Neue, Arial, sans-serif"
          font-weight="700" font-size="22"
          fill="#94a3b8">YOUR LOGO HERE</text>
  </svg>
  <div class="pill"><span class="dot"></span><span>En attente de configuration</span></div>
  <div class="host">{hostname}</div>
</div>
</body></html>"""
    url = 'data:text/html;base64,' + base64.b64encode(html.encode()).decode()
    launch_chromium(url)

import socketio
sio = socketio.Client(reconnection=True, reconnection_attempts=0,
                      reconnection_delay=2, reconnection_delay_max=10)

@sio.on('remote_authorize')
def on_auth(data):
    u = (data or {}).get('url')
    if u:
        launch_chromium(u)

@sio.on('force_relaunch')
def on_rel(data=None):
    show_wait_screen()

@sio.event
def connect():
    print('✅ Connecté au master')
    try:
        sio.emit('register_request', {'hostname': os.uname()[1]})
    except Exception as e:
        print(f'register_request: {e}')

@sio.event
def disconnect():
    print('🔌 Déconnecté du master')

def _heartbeat_loop():
    """Heartbeat toutes les HEARTBEAT_S secondes pour rester 'online'."""
    while True:
        try:
            if sio.connected:
                sio.emit('heartbeat', {'hostname': os.uname()[1]})
        except Exception:
            pass
        time.sleep(HEARTBEAT_S)

def _chromium_monitor():
    """Si Chromium meurt et qu'on a une URL active, on relance."""
    while True:
        time.sleep(30)
        try:
            subprocess.check_output(['pgrep', '-f', 'chromium'],
                                    stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            if _current_url:
                launch_chromium(_current_url)

def _main():
    print(f'🎯 Master cible : {MASTER_IP}:{PORT}')
    setup_kiosk()
    show_wait_screen()
    threading.Thread(target=_chromium_monitor, daemon=True).start()
    threading.Thread(target=_heartbeat_loop, daemon=True).start()

    while True:
        if not sio.connected:
            try:
                sio.connect(f'http://{MASTER_IP}:{PORT}')
            except Exception:
                time.sleep(5)
        time.sleep(10)

if __name__ == '__main__':
    _main()
