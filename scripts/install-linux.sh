#!/bin/sh
set -eu

fail() {
    printf 'erreur: %s\n' "$1" >&2
    exit 1
}

[ "$(uname -s)" = "Linux" ] \
    || fail "ce script est pour Linux; voir docs/PRIVILEGES.md pour FreeBSD et macOS"

command -v setcap >/dev/null 2>&1 \
    || fail "setcap est introuvable (paquet libcap2-bin sur Debian/Ubuntu, libcap sur Arch/Manjaro/Fedora)"

BIN="${1:-}"
if [ -z "$BIN" ]; then
    if [ -x /usr/local/bin/mysniffer ]; then
        BIN=/usr/local/bin/mysniffer
    elif [ -x ./build/mysniffer ]; then
        BIN=./build/mysniffer
    else
        fail "aucun binaire trouve; compilez-le (cmake --build build) ou passez son chemin en argument"
    fi
fi

[ -x "$BIN" ] || fail "$BIN n existe pas ou n est pas executable"

printf 'Octroi de cap_net_raw a %s (mot de passe administrateur demande)...\n' "$BIN"
sudo setcap cap_net_raw+ep "$BIN"

getcap "$BIN" | grep -q cap_net_raw || fail "le droit n a pas ete applique correctement"

printf '\n'
printf 'Termine. Le programme peut maintenant capturer sans sudo:\n\n'
printf '  %s capture\n\n' "$BIN"
printf 'Rappel: ce droit est attache au fichier binaire. Il disparait si vous\n'
printf 'recompilez ou recopiez le programme ailleurs; relancez alors ce script.\n'
