#!/bin/sh
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
PCAP="${1:-}"

[ -n "$PCAP" ] || { echo "usage: $0 capture.pcap" >&2; exit 1; }
[ -f "$PCAP" ] || { echo "erreur: $PCAP n'existe pas" >&2; exit 1; }

command -v tcpdump >/dev/null 2>&1 \
    || { echo "erreur: tcpdump n'est pas installe (sudo pacman -S tcpdump)" >&2; exit 1; }

BINARY="$ROOT/build/mysniffer"
[ -x "$BINARY" ] || { echo "erreur: compilez d'abord ($BINARY est absent)" >&2; exit 1; }

ours=$(mktemp)
theirs=$(mktemp)
trap 'rm -f "$ours" "$theirs"' EXIT

"$BINARY" read -r "$PCAP" 2>/dev/null \
    | sed -n 's/^\([0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]*\).*[[:space:]]\([0-9.]*\):\([0-9]*\) > \([0-9.]*\):\([0-9]*\).*/\1 \2.\3 > \4.\5/p' \
    > "$ours"

tcpdump -r "$PCAP" -n 2>/dev/null \
    | sed -e 's/ IP \[[^]]*\] (invalid) / IP /' \
          -e 's/ IP truncated-ip[^!]*! / IP /' \
    | sed -n 's/^\([0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]*\) IP \([0-9.]*\) > \([0-9.]*\):.*/\1 \2 > \3/p' \
    > "$theirs"

mine=$(wc -l < "$ours" | tr -d ' ')
other=$(wc -l < "$theirs" | tr -d ' ')

printf '\n'
printf '  paquets IPv4 avec ports extraits par nous     : %s\n' "$mine"
printf '  paquets IPv4 avec ports extraits par tcpdump  : %s\n' "$other"
printf '\n'

if [ "$mine" -eq 0 ]; then
    echo "  Aucun paquet TCP ou UDP dans cette capture: rien a comparer."
    exit 0
fi

if diff -q "$ours" "$theirs" >/dev/null 2>&1; then
    printf '  Les deux outils extraient EXACTEMENT les memes heures,\n'
    printf '  les memes adresses et les memes ports, sur les %s paquets.\n\n' "$mine"
    exit 0
fi

printf '  Des differences existent. Notre lecture a gauche, tcpdump a droite:\n\n'
diff -y --width=110 "$ours" "$theirs" | grep -E '[|<>]' | head -20
printf '\n'
exit 1
