#!/bin/bash
# Exécuter avec sudo : sudo bash install.sh [MASTER_IP]

MASTER_IP="${1:-YOUR_MASTER_IP}"
SCREENMANAGER_USER="screenuser"
SESSION_USER="YOUR_SESSION_USER"   # user de session (peut aussi être "pi" selon le système)
ENDPOINT_SCRIPT="/home/$SESSION_USER/endpoint.py"

echo "=== Configuration SCREEN MANAGER Endpoint ==="
echo "Master IP : $MASTER_IP"
echo ""

# 1. Dépendances système
echo "[1/8] Installation des dépendances..."
apt update && apt install -y \
    chromium-browser \
    python3-pip \
    x11-xserver-utils \
    xdotool \
    wmctrl \
    unclutter \
    openssh-server \
    sshpass \
    curl

# 2. Installation Python
echo "[2/7] Installation des paquets Python..."
pip3 install python-socketio[client] requests --break-system-packages

# 3. Créer l'utilisateur disscreen pour accès SSH distant du Master
echo "[3/7] Création de l'utilisateur SSH '$SCREENMANAGER_USER'..."
if ! id "$SCREENMANAGER_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$SCREENMANAGER_USER"
    passwd -l "$SCREENMANAGER_USER"  # Désactiver la connexion par mot de passe
    echo "  → Utilisateur $SCREENMANAGER_USER créé (SSH uniquement — accès Master)."
else
    echo "  → Utilisateur $SCREENMANAGER_USER existe déjà."
fi

# Ajouter disscreen au groupe systemd-journal pour lire les logs sans sudo
usermod -aG systemd-journal "$SCREENMANAGER_USER" 2>/dev/null || true

# 4. Configurer les droits sudo limités (restart/stop/start/status du service)
echo "[4/7] Configuration des droits sudo pour $SCREENMANAGER_USER..."
SYSTEMCTL_PATH=$(which systemctl 2>/dev/null || echo "/usr/bin/systemctl")
cat > /etc/sudoers.d/disscreen <<EOF
# Droits sudo SCREEN MANAGER — généré par install.sh
$SCREENMANAGER_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH restart disscreen
$SCREENMANAGER_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH stop disscreen
$SCREENMANAGER_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH start disscreen
$SCREENMANAGER_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH status disscreen
$SCREENMANAGER_USER ALL=(ALL) NOPASSWD: /bin/cp /tmp/endpoint_new.py /home/$SESSION_USER/endpoint.py

# Droits sudo pour le user de session (accès direct master sans install.sh préalable)
$SESSION_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH restart disscreen
$SESSION_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH stop disscreen
$SESSION_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH start disscreen
$SESSION_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH status disscreen
$SESSION_USER ALL=(ALL) NOPASSWD: /bin/cp /tmp/endpoint_new.py /home/$SESSION_USER/endpoint.py
EOF
chmod 440 /etc/sudoers.d/disscreen
echo "  → Sudoers configuré."

# 5. Configurer les clés SSH autorisées
echo "[5/7] Configuration SSH (récupération de la clé du Master)..."
mkdir -p /home/$SCREENMANAGER_USER/.ssh
chmod 700 /home/$SCREENMANAGER_USER/.ssh

MASTER_KEY=$(curl -s --connect-timeout 10 "http://$MASTER_IP:5002/api/master-pubkey" 2>/dev/null)
if [ -n "$MASTER_KEY" ]; then
    echo "$MASTER_KEY" > /home/$SCREENMANAGER_USER/.ssh/authorized_keys
    chmod 600 /home/$SCREENMANAGER_USER/.ssh/authorized_keys
    chown -R $SCREENMANAGER_USER:$SCREENMANAGER_USER /home/$SCREENMANAGER_USER/.ssh
    echo "  ✅ Clé SSH du Master configurée."
else
    echo "  ⚠️  Impossible de récupérer la clé du Master (http://$MASTER_IP:5002 inaccessible)."
    echo "      Configurez manuellement : /home/$SCREENMANAGER_USER/.ssh/authorized_keys"
fi

# Activer le serveur SSH
systemctl enable ssh
systemctl restart ssh
echo "  → SSH activé."

# 6. Autostart LXDE — On prépare l'environnement mais le lancement est géré par Systemd
echo "[6/7] Configuration autostart LXDE..."

# Détection de l'utilisateur de session (YOUR_SESSION_USER ou pi)
if id "$SESSION_USER" &>/dev/null; then
    REAL_USER="$SESSION_USER"
elif id "pi" &>/dev/null; then
    REAL_USER="pi"
else
    REAL_USER=$(logname 2>/dev/null || echo "root")
fi

# Niveau système (fallback)
mkdir -p /etc/xdg/lxsession/LXDE-pi
cat > /etc/xdg/lxsession/LXDE-pi/autostart <<EOF
@xset s off
@xset -dpms
@xset s noblank
EOF

# Niveau user (prioritaire)
for USER_HOME in /home/pi "/home/$SESSION_USER" "/home/$REAL_USER"; do
    if [ -d "$USER_HOME" ]; then
        USR=$(basename "$USER_HOME")
        mkdir -p "$USER_HOME/.config/lxsession/LXDE-pi"
        cat > "$USER_HOME/.config/lxsession/LXDE-pi/autostart" <<EOF
@xset s off
@xset -dpms
@xset s noblank
EOF
        chown -R "$USR:$USR" "$USER_HOME/.config/lxsession" 2>/dev/null || true
        echo "  → Autostart optimisé pour $USR."
    fi
done

# 7a. Forcer X11 (désactiver Wayland) — indispensable pour le mode kiosk GNOME
echo "[7a] Désactivation de Wayland (force X11)..."
GDM_CONF="/etc/gdm3/custom.conf"
if [ -f "$GDM_CONF" ]; then
    # Décommenter WaylandEnable si présent, sinon l'ajouter sous [daemon]
    if grep -qE "^\s*#?\s*WaylandEnable" "$GDM_CONF"; then
        sed -i 's/^\s*#\?\s*WaylandEnable.*/WaylandEnable=false/' "$GDM_CONF"
    elif grep -q "^\[daemon\]" "$GDM_CONF"; then
        sed -i '/^\[daemon\]/a WaylandEnable=false' "$GDM_CONF"
    else
        printf '\n[daemon]\nWaylandEnable=false\n' >> "$GDM_CONF"
    fi
    echo "  → WaylandEnable=false ajouté dans $GDM_CONF (X11 forcé)."
else
    echo "  ⚠️  $GDM_CONF introuvable — vérifiez que gdm3 est bien installé."
fi

# 7. Désactivation PERMANENTE de la mise en veille
echo "[7/8] Désactivation permanente de la mise en veille..."

# Masquer les targets systemd de veille
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null || true

# Configurer systemd-sleep
cat > /etc/systemd/sleep.conf <<EOF
[Sleep]
AllowSuspend=no
AllowHibernation=no
AllowHybridSleep=no
AllowSuspendThenHibernate=no
EOF

# Config X11 : désactiver DPMS et screensaver au démarrage du serveur X
mkdir -p /etc/X11/xorg.conf.d
cat > /etc/X11/xorg.conf.d/10-no-dpms.conf <<EOF
Section "ServerFlags"
    Option "BlankTime"   "0"
    Option "StandbyTime" "0"
    Option "SuspendTime" "0"
    Option "OffTime"     "0"
EndSection

Section "Extensions"
    Option "DPMS" "Disable"
EndSection
EOF

# Raspberry Pi : désactiver le blanking HDMI
if [ -f /boot/config.txt ]; then
    grep -q "hdmi_blanking=0" /boot/config.txt || echo "hdmi_blanking=0" >> /boot/config.txt
fi
if [ -f /boot/firmware/config.txt ]; then
    grep -q "hdmi_blanking=0" /boot/firmware/config.txt || echo "hdmi_blanking=0" >> /boot/firmware/config.txt
fi

# Désactiver xscreensaver
systemctl disable xscreensaver 2>/dev/null || true
pkill xscreensaver 2>/dev/null || true
echo "  → Mise en veille désactivée définitivement."

# 8. Service systemd
echo "[8/8] Création du service systemd..."
REAL_UID=$(id -u "$REAL_USER" 2>/dev/null || echo "1000")
XAUTH_PATH="/home/$REAL_USER/.Xauthority"
[ "$REAL_USER" = "root" ] && XAUTH_PATH="/root/.Xauthority"

cat > /etc/systemd/system/disscreen.service <<EOF
[Unit]
Description=ScreenManager Endpoint Client
After=network.target graphical-session.target display-manager.service
Wants=graphical.target

[Service]
# Attendre que la session graphique soit disponible (X11 ou Wayland)
ExecStartPre=/bin/bash -c "\
  for i in \$(seq 1 30); do \
    [ -f $XAUTH_PATH ] && break; \
    [ -S /run/user/$REAL_UID/wayland-0 ] && break; \
    sleep 2; \
  done"
ExecStart=/usr/bin/python3 $ENDPOINT_SCRIPT
Restart=always
RestartSec=10
User=$REAL_USER
Environment=DISPLAY=:0
Environment=XAUTHORITY=$XAUTH_PATH
Environment=WAYLAND_DISPLAY=wayland-0
Environment=XDG_RUNTIME_DIR=/run/user/$REAL_UID

[Install]
WantedBy=graphical.target
EOF

systemctl daemon-reload
systemctl enable disscreen.service

echo ""
echo "=== Installation terminée ! ==="
echo ""
echo "Prochaines étapes :"
echo "  1. Vérifiez l'IP du Master dans $ENDPOINT_SCRIPT"
echo "  2. Redémarrez l'endpoint : sudo reboot"
echo ""
echo "Depuis l'interface web Master (http://$MASTER_IP:5002) :"
echo "  - Approuver l'écran dans 'Flotte'"
echo "  - Configurer la playlist"
echo "  - Voir les logs, restart, déployer des mises à jour"
echo "  - Gérer le plan de salle (onglet Plan)"
