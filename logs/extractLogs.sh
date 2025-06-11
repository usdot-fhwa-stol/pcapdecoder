#!/usr/bin/bash
set -euo pipefail

# ---- CONFIGURATION ----
# Pre-set these. If you leave them blank, they will be prompted for:
REMOTE_USER=""
REMOTE_HOST=""
REMOTE_PATH=""
# -----------------------

# Prompt if any variable is empty
if [[ -z "$REMOTE_USER" ]]; then
  read -rp "Enter remote user (e.g. root): " REMOTE_USER
fi

if [[ -z "$REMOTE_HOST" ]]; then
  read -rp "Enter remote host (e.g. 192.168.0.54): " REMOTE_HOST
fi

if [[ -z "$REMOTE_PATH" ]]; then
  read -rp "Enter remote path (e.g. /tmp/log/*.syslog): " REMOTE_PATH
fi

# Copy
echo "Copying from ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH} → $(pwd)/"
scp -r "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}" ./

echo "Done."
