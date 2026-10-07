#!/usr/bin/env bash

# Эталон для сравнения: WireGuard в ядре между n1 и n2, overlay 10.98.0.0/24
# Использование: wg-baseline.sh up | bench | down

set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"

KEYDIR=$(mktemp -d)
PIDFILE=/tmp/gomesh-iperf3-n2.pid
cleanup() {
    rm -rf "$KEYDIR"
    [[ -f $PIDFILE ]] && kill "$(cat "$PIDFILE")" 2>/dev/null
    rm -f "$PIDFILE"
}
trap cleanup EXIT

down() {
    for ns in n1 n2; do
        ip -n "$ns" link del wg0 2>/dev/null || true
    done
}

setup() { # ns idx peer peer_idx
    local ns=$1 idx=$2 peer=$3 pidx=$4
    ip -n "$ns" link add wg0 type wireguard
    ip netns exec "$ns" wg set wg0 \
        private-key "$KEYDIR/$ns.key" listen-port 51820 \
        peer "$(cat "$KEYDIR/$peer.pub")" \
        endpoint "192.168.77.$pidx:51820" \
        allowed-ips "10.98.0.$pidx/32"
    ip -n "$ns" addr add "10.98.0.$idx/24" dev wg0
    ip -n "$ns" link set wg0 up
}

up() {
    down
    for ns in n1 n2; do
        wg genkey > "$KEYDIR/$ns.key"
        wg pubkey < "$KEYDIR/$ns.key" > "$KEYDIR/$ns.pub"
    done
    setup n1 1 n2 2
    setup n2 2 n1 1
    ip netns exec n1 ping -c 2 -W 1 10.98.0.2 >/dev/null && echo "WireGuard-туннель n1 <-> n2 работает"
}

bench() {
    ip netns exec n2 iperf3 -s -D --pidfile "$PIDFILE"
    sleep 0.5
    # 192.168.77.2 — голый underlay (потолок), 10.98.0.2 — через WireGuard
    for target in 192.168.77.2 10.98.0.2; do
        echo "== $target, 1 поток"
        ip netns exec n1 iperf3 -c "$target" -t 10 | tail -n 4
        echo "== $target, 8 потоков"
        ip netns exec n1 iperf3 -c "$target" -t 10 -P 8 | tail -n 4
    done
}

case ${1:-} in
    up)    up ;;
    bench) bench ;;
    down)  down ;;
    *)     echo "usage: $0 up|bench|down" >&2; exit 2 ;;
esac
