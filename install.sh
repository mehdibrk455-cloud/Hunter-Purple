#!/usr/bin/env bash
# ==============================================================================
# HUNTER — Automated Purple Team Framework & System Defense Suite
# Installation script for Ubuntu / Debian-based Linux systems
# ==============================================================================

set -euo pipefail

# Couleurs ANSI pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ------------------------------------------------------------------------------
# 1. Vérification des privilèges Root / Sudo
# ------------------------------------------------------------------------------
echo -e "${CYAN}${BOLD}"
echo "================================================================================"
echo "          HUNTER — AUTOMATED PURPLE TEAM & SYSTEM DEFENSE FRAMEWORK             "
echo "                             INSTALLATION SCRIPT                                "
echo "================================================================================"
echo -e "${NC}"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo -e "${RED}[!] ERREUR : Ce script doit être exécuté avec les privilèges root (sudo).${NC}"
    echo -e "${YELLOW}[*] Usage : sudo ./install.sh${NC}"
    echo -e "${RED}[!] ERROR : This script must be executed with root privileges (sudo).${NC}"
    echo -e "${YELLOW}[*] Usage : sudo ./install.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Privilèges administrateur (root) validés.${NC}"
echo -e "${GREEN}[+] Root administrative privileges confirmed.${NC}\n"

# ------------------------------------------------------------------------------
# 2. Installation des dépendances système (compilateur, libpcap, etc.)
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Étape 1/4 : Mise à jour des dépôts et installation des paquets système...${NC}"
echo -e "${CYAN}[*] Step 1/4 : Updating repositories and installing system packages...${NC}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    pkg-config \
    libssl-dev \
    curl \
    git \
    ufw \
    ca-certificates

echo -e "${GREEN}[✓] Dépendances système installées avec succès.${NC}\n"

# ------------------------------------------------------------------------------
# 3. Vérification de l'environnement Rust / Cargo
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Étape 2/4 : Vérification de la chaîne de compilation Rust...${NC}"
echo -e "${CYAN}[*] Step 2/4 : Checking Rust compilation toolchain...${NC}"

TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)

# Détection de cargo dans l'environnement de l'utilisateur ou système
if [ -f "$USER_HOME/.cargo/bin/cargo" ]; then
    export PATH="$USER_HOME/.cargo/bin:$PATH"
elif [ -f "/root/.cargo/bin/cargo" ]; then
    export PATH="/root/.cargo/bin:$PATH"
fi

if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}[!] Cargo/Rust introuvable. Installation automatique de Rustup...${NC}"
    echo -e "${YELLOW}[!] Cargo/Rust not found. Automatically installing Rustup...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    export PATH="$USER_HOME/.cargo/bin:/root/.cargo/bin:$PATH"
fi

echo -e "${GREEN}[✓] Chaîne Rust opérationnelle : $(cargo --version)${NC}\n"

# ------------------------------------------------------------------------------
# 4. Compilation optimisée du projet en mode Release
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Étape 3/4 : Compilation du binaire Hunter en mode release optimisé...${NC}"
echo -e "${CYAN}[*] Step 3/4 : Compiling Hunter binary in optimized release mode...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Compilation en tant qu'utilisateur standard si sudo a été utilisé pour éviter les problèmes de droits dans target/
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    sudo -u "$SUDO_USER" env PATH="$PATH" cargo build --release
else
    cargo build --release
fi

# Localisation du binaire généré (gère la casse Hunter / hunter)
BIN_PATH=""
if [ -f "$SCRIPT_DIR/target/release/Hunter" ]; then
    BIN_PATH="$SCRIPT_DIR/target/release/Hunter"
elif [ -f "$SCRIPT_DIR/target/release/hunter" ]; then
    BIN_PATH="$SCRIPT_DIR/target/release/hunter"
else
    echo -e "${RED}[!] ERREUR : La compilation a échoué. Le binaire release est introuvable.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Compilation terminée avec succès : $BIN_PATH${NC}\n"

# ------------------------------------------------------------------------------
# 5. Déploiement global dans /usr/local/bin/hunter
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Étape 4/4 : Déploiement du binaire dans les commandes globales Linux (/usr/local/bin/hunter)...${NC}"
echo -e "${CYAN}[*] Step 4/4 : Deploying binary to global Linux path (/usr/local/bin/hunter)...${NC}"

INSTALL_DEST="/usr/local/bin/hunter"
cp "$BIN_PATH" "$INSTALL_DEST"
chmod 755 "$INSTALL_DEST"

# ------------------------------------------------------------------------------
# 6. Bannière de succès & instructions d'utilisation bilingues
# ------------------------------------------------------------------------------
echo -e "${GREEN}${BOLD}"
echo "================================================================================"
echo "                  HUNTER A ÉTÉ INSTALLÉ AVEC SUCCÈS !                          "
echo "                 HUNTER HAS BEEN SUCCESSFULLY INSTALLED!                        "
echo "================================================================================"
echo -e "${NC}"
echo -e "Le binaire global est désormais accessible depuis n'importe quel terminal :"
echo -e "The global binary is now available system-wide:"
echo -e "  ${CYAN}${BOLD}$INSTALL_DEST${NC}\n"

echo -e "${BOLD}EXEMPLES D'UTILISATION / USAGE EXAMPLES :${NC}"
echo -e "  ${YELLOW}1. Catalogue d'aide détaillé des scénarios (en français) :${NC}"
echo -e "     hunter --auto-defend help -fr\n"
echo -e "  ${YELLOW}2. Complete scenario help catalog (in English) :${NC}"
echo -e "     hunter --auto-defend help\n"
echo -e "  ${YELLOW}3. Audit Web complet OWASP Top 10 :${NC}"
echo -e "     hunter -owasp http://localhost:3000 -fr\n"
echo -e "  ${YELLOW}4. Contrôle de sécurité & remédiation de la machine hôte :${NC}"
echo -e "     sudo hunter --auto-defend localhost -check all -fr\n"
echo -e "  ${YELLOW}5. Test individuel d'un scénario de défense :${NC}"
echo -e "     sudo hunter --auto-defend localhost -check firewall_policy -fr\n"

echo -e "${GREEN}[✓] Prêt pour vos opérations Purple Team & Durcissement Système !${NC}"
echo -e "${GREEN}[✓] Ready for Purple Team operations & Defensive Hardening!${NC}"
