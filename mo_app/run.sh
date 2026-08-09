#!/usr/bin/env bash
# One-click launcher for the WiFi Packet Capture app.
#
# Capturing packets needs root. This script uses real sudo (proven to work
# on your hardware) rather than file capabilities, which turned out to be
# unreliable for this setup even when correctly granted.
#
# First run: sets up a Python environment and installs dependencies, then
# asks for your sudo password to start the app.
#
# To stop it asking for a password every time, install the scoped sudoers
# rule described in wifi-capture-sudoers (see README.md, "Passwordless
# launch"). Once installed, this script detects it automatically and skips
# the prompt.
set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
    echo "First run: setting up a Python environment..."
    if ! python3 -m venv venv; then
        echo
        echo "Could not create the virtual environment."
        echo "Try:  sudo apt install python3-venv   (or python3.12-venv)"
        echo "Then run this again."
        exit 1
    fi
fi

if ! venv/bin/python3 -c "import flask, scapy" >/dev/null 2>&1; then
    echo "First run: installing dependencies (flask, scapy)..."
    venv/bin/pip install --quiet --upgrade pip
    venv/bin/pip install --quiet flask scapy
fi

echo
echo "Starting WiFi Packet Capture..."
echo "Open on this computer: http://localhost:5000"
IPS=$(hostname -I 2>/dev/null)
if [ -n "$IPS" ]; then
    echo "Open from another device on your network (LAN or WiFi), using whichever address matches that network:"
    for ip in $IPS; do
        echo "  http://$ip:5000"
    done
fi
echo

APP_PY="$(pwd)/venv/bin/python3"
APP_MAIN="$(pwd)/app.py"

# Try without a password first (works once the sudoers rule below is installed).
if sudo -n "$APP_PY" "$APP_MAIN"; then
    exit 0
fi

echo "(Passwordless launch isn't set up yet — asking for your sudo password. See README.md, \"Passwordless launch\", to stop this prompt in future.)"
exec sudo "$APP_PY" "$APP_MAIN"
