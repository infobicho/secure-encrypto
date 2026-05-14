#!/usr/bin/env bash
# ============================================================
#  secure-encrypto — Installation script (Linux / macOS)
# ============================================================
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗"
echo "  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝"
echo "  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  "
echo "  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  "
echo "  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗"
echo "  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo "  secure-encrypto v2.0 — Installateur"
echo "  ──────────────────────────────────────────────────"
echo ""

# Check Python 3.9+
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ Python 3 non trouvé. Installez Python 3.9+ depuis python.org${NC}"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "  ✓ Python $PY_VER trouvé"

# Check pip
if ! python3 -m pip --version &>/dev/null; then
    echo -e "${RED}  ✗ pip non trouvé. Installez pip : https://pip.pypa.io${NC}"
    exit 1
fi

# Install dependencies
echo ""
echo "  → Installation des dépendances…"
python3 -m pip install --upgrade pip -q
python3 -m pip install -r requirements.txt -q

echo -e "${GREEN}  ✓ Dépendances installées${NC}"

# Créer le dossier de configuration et de logs
LOG_DIR="${HOME}/.config/secure-encrypto"
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    echo -e "  ✓ Dossier de logs créé : $LOG_DIR"
else
    echo -e "  ✓ Dossier de logs déjà présent : $LOG_DIR"
fi

echo ""
echo "  ──────────────────────────────────────────────────"
echo -e "${GREEN}  ✅  Installation terminée !${NC}"
echo ""
echo "  Démarrage :"
echo "     python3 main.py"
echo ""
