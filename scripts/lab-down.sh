#!/usr/bin/env bash

# Сносит стенд. Идемпотентный: повторный запуск не падает.
set -uo pipefail
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"
 
BR=br-mesh
 
# Удаление namespace уничтожает eth0 внутри, а вместе с ним и вторую половину veth
for ns in n1 n2 n3; do
    ip netns del "$ns" 2>/dev/null || true
done
 
ip link del "$BR" 2>/dev/null || true
 
if command -v iptables >/dev/null; then
    while iptables -D FORWARD -i "$BR" -o "$BR" -j ACCEPT 2>/dev/null; do :; done
fi

exit 0
