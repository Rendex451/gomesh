#!/usr/bin/env bash

# Поднимает стенд: bridge br-mesh + 3 namespace (n1..n3) в underlay 192.168.77.0/24
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"

BR=br-mesh
NODES=(n1 n2 n3)
NET=192.168.77

# Всегда стартуем с чистого листа — так lab-up идемпотентен
"$(dirname "$0")/lab-down.sh"

ip link add "$BR" type bridge
ip link set "$BR" up

for i in "${!NODES[@]}"; do
    ns=${NODES[$i]}
    idx=$((i + 1))

    ip netns add "$ns"
    # Один конец veth остаётся в root-namespace и цепляется к bridge,
    # другой сразу уезжает в namespace под именем eth0
    ip link add "veth-$ns" type veth peer name eth0 netns "$ns"
    ip link set "veth-$ns" master "$BR" up

    ip -n "$ns" addr add "$NET.$idx/24" dev eth0
    ip -n "$ns" link set eth0 up
    ip -n "$ns" link set lo up
done

# Если загружен br_netfilter (обычно из-за Docker), трафик через bridge
# проходит цепочку FORWARD, где у Docker политика DROP. Разрешаем свой bridge.
if [[ -r /proc/sys/net/bridge/bridge-nf-call-iptables ]] &&
   [[ $(cat /proc/sys/net/bridge/bridge-nf-call-iptables) == 1 ]] &&
   command -v iptables >/dev/null; then
    iptables -I FORWARD -i "$BR" -o "$BR" -j ACCEPT
fi

echo "стенд поднят: ${NODES[*]} в $NET.0/24"
