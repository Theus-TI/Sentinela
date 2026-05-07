#!/bin/bash
# Sentinel EDR - Script de Inicialização com Venv
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -d "$SCRIPT_DIR/.venv" ]; then
    echo "🛡️ Iniciando Sentinel EDR com privilégios elevados..."
    sudo "$SCRIPT_DIR/.venv/bin/python3" "$SCRIPT_DIR/sentinel.py" "$@"
else
    echo "⚠️  Venv não encontrado. Criando ambiente de segurança..."
    python3 -m venv "$SCRIPT_DIR/.venv"
    "$SCRIPT_DIR/.venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
    sudo "$SCRIPT_DIR/.venv/bin/python3" "$SCRIPT_DIR/sentinel.py" "$@"
fi
