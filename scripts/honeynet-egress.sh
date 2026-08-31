#!/usr/bin/env sh
# Drop outbound traffic from the decoy subnet.
#
# Inbound published ports keep working; the decoys just cannot reach anything
# outward. Run this once per boot, before exposing any decoy port.
#
# NOTE: do NOT use `internal: true` on the honeynet in compose instead. It kills
# the published ports the decoys need, which makes them unreachable and the whole
# honeypot pointless. `internal: true` is only right for a network that publishes
# nothing at all.
#
#   sudo ./scripts/honeynet-egress.sh          apply
#   sudo ./scripts/honeynet-egress.sh --remove remove
#   sudo ./scripts/honeynet-egress.sh --check  show current rules

set -eu

SUBNET="${ST_HONEYNET_SUBNET:-172.30.0.0/24}"
CHAIN="DOCKER-USER"

if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables not found. On Docker Desktop (macOS/Windows) this script does not" >&2
    echo "apply — run the stack in a Linux VM where the DOCKER-USER chain exists." >&2
    exit 1
fi

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

rule_args="-s $SUBNET ! -d $SUBNET -j DROP"

case "${1:-}" in
    --check)
        iptables -L "$CHAIN" -n --line-numbers
        exit 0
        ;;
    --remove)
        # shellcheck disable=SC2086
        while iptables -C "$CHAIN" $rule_args 2>/dev/null; do
            # shellcheck disable=SC2086
            iptables -D "$CHAIN" $rule_args
        done
        echo "removed egress drop for $SUBNET"
        exit 0
        ;;
esac

# shellcheck disable=SC2086
if iptables -C "$CHAIN" $rule_args 2>/dev/null; then
    echo "egress drop for $SUBNET already present"
else
    # shellcheck disable=SC2086
    iptables -I "$CHAIN" 1 $rule_args
    echo "egress dropped for $SUBNET (inbound published ports unaffected)"
fi

echo
echo "Verify from inside a decoy — this must fail:"
echo "    docker exec st-web python -c \"import socket;socket.create_connection(('1.1.1.1',53),3)\""
