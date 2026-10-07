#!/usr/bin/env bash
# Генерирует lab/n1.toml..lab/nN.toml для стенда из network namespaces.
# Нода n1 — seed, остальные знают только её. Статические пиры нужны на
# этапах 1–2, пока нет gossip.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077   # в файлах приватные ключи

BIN=./bin/gomesh
N=${N:-3}
PORT=51900

[[ -x $BIN ]] || { echo "нет $BIN — сначала make build" >&2; exit 1; }
mkdir -p lab

declare -a PRIV PUB
for i in $(seq 1 "$N"); do
    PRIV[i]=$("$BIN" genkey)
    PUB[i]=$(echo "${PRIV[i]}" | "$BIN" pubkey)
done

for i in $(seq 1 "$N"); do
    f=lab/n$i.toml
    {
        echo "# сгенерировано scripts/gen-lab-config.sh — нода n$i"
        echo "private_key = \"${PRIV[i]}\""
        echo "listen_port = $PORT"
        echo "tun_name    = \"gomesh0\""
        echo "tun_address = \"10.99.$i.1/16\""
        echo "subnet      = \"10.99.$i.0/24\""
        if (( i == 1 )); then
            echo "seeds       = []"
        else
            echo "seeds       = [\"192.168.77.1:$PORT\"]"
        fi
        for j in $(seq 1 "$N"); do
            (( j == i )) && continue
            echo
            echo "[[peers]]"
            echo "public_key = \"${PUB[j]}\""
            echo "endpoint   = \"192.168.77.$j:$PORT\""
            echo "subnets    = [\"10.99.$j.0/24\"]"
        done
    } > "$f"
    "$BIN" check -config "$f"
done
