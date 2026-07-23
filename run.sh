#!/usr/bin/env bash
# NGAP / NAS Wireshark Diagnostic Analyzer - Cross-Platform macOS / Linux Launcher

echo "===================================================="
echo "  NGAP / NAS Wireshark Diagnostic Analyzer"
echo "  Cross-Platform macOS / Linux Launcher"
echo "===================================================="
echo ""

# Determine python command
if command -v python3 &>/dev/null; then
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    PY_CMD="python"
else
    echo "[!] Error: Python 3 is not installed or not in PATH."
    exit 1
fi

if [ -z "$1" ]; then
    echo "[+] Launching Web GUI Dashboard on http://localhost:8080 ..."
    $PY_CMD main.py --gui
else
    echo "[+] Analyzing capture file: $1"
    $PY_CMD main.py -f "$@"
fi
