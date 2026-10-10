#!/bin/sh
set -eu

fail() {
    printf 'erreur: %s\n' "$1" >&2
    exit 1
}

[ "$(uname -s)" = "Darwin" ] \
    || fail "ce script est pour macOS; voir docs/PRIVILEGES.md pour Linux, FreeBSD et Windows"

GROUP=access_bpf
USER_NAME=$(id -un)

if ! dscl . -read /Groups/$GROUP >/dev/null 2>&1; then
    fail "le groupe $GROUP n existe pas: il est cree par Wireshark. Installez
Wireshark (il suffit du programme, pas besoin de l utiliser), relancez ce
script, ou sinon utilisez: sudo ./build/mysniffer capture"
fi

if id -nG "$USER_NAME" | grep -qw "$GROUP"; then
    printf '%s appartient deja au groupe %s.\n' "$USER_NAME" "$GROUP"
else
    printf 'Ajout de %s au groupe %s (mot de passe administrateur demande)...\n' "$USER_NAME" "$GROUP"
    sudo dseditgroup -o edit -a "$USER_NAME" -t user "$GROUP"
fi

printf '\n'
printf 'Termine. Deconnectez-vous puis reconnectez-vous pour que le nouveau\n'
printf 'groupe prenne effet. Ensuite:\n\n'
printf '  ./build/mysniffer capture\n\n'
printf 'devrait marcher sans sudo.\n'
