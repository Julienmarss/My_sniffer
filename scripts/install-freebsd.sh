#!/bin/sh
set -eu

fail() {
    printf 'erreur: %s\n' "$1" >&2
    exit 1
}

[ "$(uname -s)" = "FreeBSD" ] \
    || fail "ce script est pour FreeBSD; voir docs/PRIVILEGES.md pour Linux, macOS et Windows"

DEVFS_CONF=/etc/devfs.conf
GROUP=network
USER_NAME=$(id -un)

if grep -q '^own[[:space:]]\+bpf\*' "$DEVFS_CONF" 2>/dev/null; then
    printf '%s configure deja bpf*, rien a ajouter.\n' "$DEVFS_CONF"
else
    printf 'Ajout des droits sur bpf* dans %s (mot de passe administrateur demande)...\n' "$DEVFS_CONF"
    printf '\n# Ajoute par scripts/install-freebsd.sh, pour que %s capture.\nown\tbpf*\troot:%s\nperm\tbpf*\t0660\n' \
        "$GROUP" "$GROUP" | sudo tee -a "$DEVFS_CONF" >/dev/null
fi

if ! pw groupshow "$GROUP" >/dev/null 2>&1; then
    printf 'Creation du groupe %s (mot de passe administrateur demande)...\n' "$GROUP"
    sudo pw groupadd "$GROUP"
fi

if id -nG "$USER_NAME" | grep -qw "$GROUP"; then
    printf '%s appartient deja au groupe %s.\n' "$USER_NAME" "$GROUP"
else
    printf 'Ajout de %s au groupe %s...\n' "$USER_NAME" "$GROUP"
    sudo pw groupmod "$GROUP" -m "$USER_NAME"
fi

printf 'Rechargement de devfs...\n'
sudo service devfs restart >/dev/null

printf '\n'
printf 'Termine. Deconnectez-vous puis reconnectez-vous pour que le nouveau\n'
printf 'groupe prenne effet (le shell actuel ne le voit pas encore). Ensuite:\n\n'
printf '  ./build/mysniffer capture\n\n'
printf 'devrait marcher sans sudo.\n'
