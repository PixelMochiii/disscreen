# ScreenManager — Gestionnaire d'affichage dynamique

Système de gestion centralisée d'écrans d'affichage (digital signage). Un **Master** (Flask + SocketIO) pilote une flotte d'**Endpoints** (scripts Python sur les écrans), chacun affichant des médias (images, vidéos, PDF) dans Chromium en mode kiosque.

## Architecture

```
┌────────────────────────────────────┐
│         Master  (port 5002)        │
│  Flask + SocketIO + SQLite         │
│  - Interface web d'administration  │
│  - Gestion des médias et playlists │
│  - Plan de salle interactif        │
│  - SSH vers les endpoints          │
└───────────────┬────────────────────┘
                │  WebSocket + SSH
    ┌───────────┼──────────────────┐
    ▼           ▼                  ▼
 Endpoint 1  Endpoint 2  ...  Endpoint N
 (Chromium kiosk sur chaque écran)
```

## Structure du projet

```
disscreen/
├── master/
│   ├── master.py           # Serveur Flask principal
│   ├── db.py               # Authentification SQLite + bcrypt
│   ├── install.sh          # Script d'installation sur les endpoints
│   ├── requirements.txt    # Dépendances Python
│   ├── .env.example        # Template de configuration (→ copier en .env)
│   ├── fleet.json          # État de la flotte (généré automatiquement)
│   ├── screenmap.json      # Plan de salle (généré automatiquement)
│   ├── templates/
│   │   ├── login.html          # Page de connexion
│   │   ├── index.html          # Interface admin principale
│   │   ├── player.html         # Lecteur kiosque (affiché sur les écrans)
│   │   └── change_password.html
│   └── static/
│       ├── logo.png            # ⚠️ PLACEHOLDER — remplacer par votre logo
│       ├── logo.svg            # ⚠️ PLACEHOLDER — remplacer par votre logo SVG
│       └── pdfjs/              # PDF.js (téléchargé au premier démarrage si absent)
└── endpoint/
    └── endpoint.py         # Client kiosque (à déployer sur chaque écran)
```

## Ce qu'il faut configurer avant de démarrer

### 1. Le logo

Remplacer les fichiers placeholder par votre logo :

- `master/static/logo.png` — logo affiché dans l'interface web (login, header)
- `master/static/logo.svg` — (optionnel) version SVG du logo

> Dans `endpoint/endpoint.py`, la fonction `show_wait_screen()` affiche également un logo SVG inline (~ligne 260). Modifier le bloc SVG pour y mettre votre logo ou votre nom d'entreprise.

### 2. Le fichier `.env`

```bash
cd master/
cp .env.example .env
```

Remplir **toutes** les valeurs dans `master/.env` :

| Variable | Description | Exemple |
|---|---|---|
| `FLASK_SECRET_KEY` | Clé secrète Flask (générer avec `python3 -c "import secrets; print(secrets.token_hex(32))"`) | `abc123...` |
| `SSH_KEY_USER` | Utilisateur SSH dédié créé par `install.sh` sur les endpoints | `screenuser` |
| `SSH_PASS_USER` | Utilisateur de session sur les endpoints (fallback avant install.sh) | `pi` ou `ubuntu` |
| `SSH_PASS` | Mot de passe SSH de l'utilisateur de session (fallback) | `your_password` |
| `INITIAL_ADMIN_PASSWORD` | Mot de passe admin au premier démarrage (forcé à changer au 1er login) | `TempPass123!` |
| `MASTER_IP` | IP LAN de la machine Master | `192.168.1.10` |

> ⚠️ Ne jamais commiter le fichier `.env` — il est dans `.gitignore`.

### 3. Les noms d'utilisateurs dans `install.sh`

En haut de `master/install.sh`, deux variables à adapter à votre environnement :

```bash
SCREENMANAGER_USER="screenuser"   # Utilisateur SSH dédié (créé par install.sh)
SESSION_USER="YOUR_SESSION_USER"  # Utilisateur de session graphique sur les endpoints
```

`SESSION_USER` est le compte Linux qui lance la session X11 sur chaque écran (souvent `pi`, `ubuntu`, ou le nom de la machine).

### 4. Le nom du service systemd

Le service s'appelle `disscreen` partout (dans `install.sh` et `master.py`). Si vous souhaitez un autre nom, faire un find/replace global sur `disscreen` dans :
- `master/install.sh`
- `master/master.py` (variables `SSH_KEY_PATH`, commentaires)

---

## Installation

### Sur le Master

```bash
# Prérequis
sudo apt install python3-pip sshpass

# Dépendances Python
cd master/
pip3 install -r requirements.txt

# Configurer
cp .env.example .env
# → éditer .env avec vos valeurs

# Démarrer
python3 master.py
# Interface disponible sur http://YOUR_MASTER_IP:5002
```

Le master crée automatiquement :
- `auth.db` (base SQLite avec le compte admin initial)
- `static/pdfjs/` (PDF.js téléchargé si absent)
- `media/` (dossiers par défaut : Evenements, RH, Sensibilisation)

### Sur chaque endpoint (écran)

Depuis l'interface web Master, onglet **Flotte** → **Provisionner** : entrer l'IP et les credentials SSH de l'écran. Le Master exécute `install.sh` à distance automatiquement.

Ou manuellement :

```bash
# Sur l'endpoint, en tant que root
curl http://YOUR_MASTER_IP:5002/download_client -o install.sh
sudo bash install.sh YOUR_MASTER_IP
sudo reboot
```

---

## Comptes utilisateurs

Au premier démarrage, un compte admin `IT` est créé avec le mot de passe défini dans `INITIAL_ADMIN_PASSWORD`.  
**Ce mot de passe est forcé à changer au premier login.**

Ensuite, gérer les comptes depuis l'interface web (onglet ⚙️ Paramètres → Utilisateurs).

> Le nom du compte admin par défaut `IT` est codé en dur dans `master/db.py` (ligne `create_user('IT', ...)`) et dans la vérification de suppression dans `master/master.py` (`if user_to_del == "IT"`). À adapter si besoin.

---

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| **Médiathèque** | Upload images (PNG/JPG/WebP/GIF), vidéos (MP4/WebM), PDF, PowerPoint (converti via LibreOffice) |
| **Playlists** | Assigner des médias à chaque écran avec timer de rotation |
| **Plan de salle** | Carte interactive avec markers cliquables par écran |
| **Flotte** | Voir statut online/offline, screenshots en temps réel, rename |
| **SSH distant** | Restart service, forcer plein écran, allumer/éteindre écran, déployer mises à jour |
| **Provisioning** | Installer et configurer un nouvel endpoint depuis l'interface web |
| **Multi-utilisateurs** | Comptes admin/user, rate limiting, changement de mot de passe forcé |

---

## Variables d'environnement (résumé)

| Fichier | Variable | Défaut | À changer |
|---|---|---|---|
| `master/.env` | `FLASK_SECRET_KEY` | *(aléatoire si absent)* | **Oui** — pour sessions persistantes |
| `master/.env` | `SSH_KEY_USER` | `screenuser` | Si autre nom d'utilisateur SSH |
| `master/.env` | `SSH_PASS_USER` | `YOUR_SESSION_USER` | **Oui** |
| `master/.env` | `SSH_PASS` | *(vide)* | **Oui** |
| `master/.env` | `INITIAL_ADMIN_PASSWORD` | `CHANGE_ME_AT_FIRST_LOGIN` | **Oui** |
| `master/.env` | `MASTER_IP` | `127.0.0.1` | **Oui** |
| `endpoint/endpoint.py` | `MASTER_IP` (conf file) | `127.0.0.1` | Via `~/.disscreen_master` |

---

## Checklist déploiement

- [ ] Remplacer `master/static/logo.png` par votre logo
- [ ] Remplacer le SVG dans `endpoint/endpoint.py` → `show_wait_screen()` par votre logo/nom
- [ ] Créer et remplir `master/.env` depuis `.env.example`
- [ ] Adapter `SESSION_USER` dans `master/install.sh`
- [ ] Démarrer le master et vérifier `http://YOUR_MASTER_IP:5002`
- [ ] Changer le mot de passe admin au premier login
- [ ] Provisionner les endpoints depuis l'interface web

---

## Dépendances

**Master (Python) :** `flask`, `flask-socketio`, `eventlet`, `python-dotenv`, `bcrypt`, `werkzeug`

**Endpoints :** `python-socketio[client]`, `requests`, `chromium` ou `chromium-browser`, `wmctrl`, `xdotool`, `unclutter`, `brightnessctl`
