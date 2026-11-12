#!/usr/bin/env bash
#
# scan_nvidia_hosts.sh
#
# Scans a /24 subnet for live hosts and checks each one
# for a specified SSH username.
#
# Usage:
#   ./scan_nvidia_hosts.sh [subnet] [username] [ssh_password]
#
# Examples:
#   ./scan_nvidia_hosts.sh
#   ./scan_nvidia_hosts.sh 192.168.120.0/24 nvidia
#   ./scan_nvidia_hosts.sh 192.168.120.0/24 ubuntu
#   ./scan_nvidia_hosts.sh 192.168.120.0/24 jetson mypassword
#
# Requires: nmap, sshpass (optional), ssh client.

set -euo pipefail

SUBNET="${1:-192.168.120.0/24}"
SSH_USER="${2:-nvidia}"
SSH_PASS="${3:-}"
SSH_TIMEOUT=3
SSH_PORT=22

# --- sanity checks -----------------------------------------------------

command -v nmap >/dev/null 2>&1 || {
    echo "nmap is required. sudo apt install nmap"
    exit 1
}

if [[ -n "$SSH_PASS" ]]; then
    command -v sshpass >/dev/null 2>&1 || {
        echo "sshpass is required for password auth. sudo apt install sshpass"
        exit 1
    }
fi

echo "Scanning $SUBNET for live hosts with SSH open (port $SSH_PORT)..."
echo "Checking SSH username: $SSH_USER"
echo

# --- discover hosts with SSH open --------------------------------------

mapfile -t LIVE_HOSTS < <(
    nmap -Pn -p"$SSH_PORT" --open -n "$SUBNET" -oG - 2>/dev/null \
        | awk '/Up$/{print $2}'
)

if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
    echo "No hosts with SSH open found on $SUBNET."
    exit 0
fi

echo "Found ${#LIVE_HOSTS[@]} host(s) with SSH open:"
printf '  %s\n' "${LIVE_HOSTS[@]}"
echo

FOUND_IPS=()

check_host() {
    local ip="$1"

    if [[ -n "$SSH_PASS" ]]; then

        if sshpass -p "$SSH_PASS" ssh \
            -o BatchMode=no \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout="$SSH_TIMEOUT" \
            -o LogLevel=ERROR \
            "${SSH_USER}@${ip}" "echo ok" >/dev/null 2>&1; then

            echo "[FOUND] $ip -- logged in as $SSH_USER"
            FOUND_IPS+=("$ip")
        fi

    else
        local out

        out=$(ssh -o BatchMode=yes \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout="$SSH_TIMEOUT" \
            -o PreferredAuthentications=none \
            -o LogLevel=ERROR \
            "${SSH_USER}@${ip}" 2>&1 || true)

        if echo "$out" | grep -qiE "permission denied|publickey|password"; then
            echo "[FOUND] $ip -- SSH server accepts auth attempts for $SSH_USER"
            FOUND_IPS+=("$ip")
        fi
    fi
}

for ip in "${LIVE_HOSTS[@]}"; do
    check_host "$ip"
done

# --- summary -----------------------------------------------------------

echo

if [[ ${#FOUND_IPS[@]} -gt 0 ]]; then
    echo "Summary: user '$SSH_USER' detected on ${#FOUND_IPS[@]} host(s):"
    printf '  %s\n' "${FOUND_IPS[@]}"
else
    echo "Summary: user '$SSH_USER' not confirmed on any scanned host."
fi
