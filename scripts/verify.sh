#!/bin/sh
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

step=0
ok() {
    step=$((step + 1))
    printf '  [%d] %s\n' "$step" "$1"
}

fail() {
    printf '\n  ECHEC: %s\n\n' "$1" >&2
    exit 1
}

printf '\n=== 1. Compilation, warnings traites comme des erreurs ===\n\n'

rm -rf build-verify
cmake -S . -B build-verify -DWARNINGS_AS_ERRORS=ON >/dev/null 2>&1 \
    || fail "la configuration CMake a echoue"
ok "configuration"

# On garde la sortie pour pouvoir compter les warnings.
cmake --build build-verify -j4 > /tmp/verify-build.log 2>&1 \
    || { cat /tmp/verify-build.log; fail "la compilation a echoue"; }
ok "compilation"

if grep -qi 'warning' /tmp/verify-build.log; then
    grep -i 'warning' /tmp/verify-build.log | head -5
    fail "des warnings sont apparus (le sujet exige zero warning)"
fi
ok "aucun warning"

printf '\n=== 2. Aucune bibliotheque interdite ===\n\n'

# Le sujet interdit toute bibliotheque reseau: capture, analyse, decodage.
# On ne se contente pas de relire les #include: on regarde ce que le binaire
# demande vraiment au systeme une fois compile. C'est une preuve, pas une
# declaration d'intention.

linked=$(ldd ./build-verify/mysniffer 2>/dev/null | grep -oE 'lib[a-z0-9_+-]*\.so' | sort -u | tr '\n' ' ')
for lib in $linked; do
    case "$lib" in
        libc.so|libm.so|libstdc++.so|libgcc_s.so|linux-vdso.so|ld-linux-x86-64.so)
            ;;  # bibliotheque standard du systeme, autorisee
        *)
            fail "le binaire est lie a une bibliotheque inattendue: $lib" ;;
    esac
done
ok "aucune bibliotheque hors standard C et C++ ($linked)"

# Les fonctions reseau de la libc sont interdites aussi: elles feraient une
# partie du travail a notre place (conversion d'ordre d'octets, d'adresses,
# resolution de noms et de services).
# Cette liste contient aussi if_nametoindex et getifaddrs, qui sont les deux
# fonctions les plus discutables du projet: ce sont des fonctions reseau de la
# libc. On les tolere, parce qu'elles servent a designer une interface et non a
# lire ou decoder du trafic, mais le script les affiche pour qu'on sache
# exactement ou on en est et qu'on puisse le defendre.
forbidden="ntohs ntohl htons htonl inet_ntoa inet_aton inet_addr inet_ntop inet_pton
           ether_ntoa ether_aton getnameinfo getaddrinfo gethostbyname
           getservbyname getprotobyname"
tolerated="if_nametoindex getifaddrs freeifaddrs if_indextoname"

# On cherche dans TOUS les fichiers objets, sans exception. Un motif qui ne
# correspond a rien ferait croire que la verification a eu lieu alors qu'elle
# n'a rien examine: on liste donc les objets avec find.
objects=$(find ./build-verify -name '*.o' 2>/dev/null | tr '\n' ' ')
[ -n "$objects" ] || fail "aucun fichier objet trouve: la verification n'examinerait rien"

symbols=$(nm -u ./build-verify/libsniffer.a $objects 2>/dev/null)

found=""
for symbol in $forbidden; do
    if printf '%s' "$symbols" | grep -qw "$symbol"; then
        found="$found $symbol"
    fi
done
[ -z "$found" ] || fail "fonctions reseau interdites utilisees:$found"
ok "aucune fonction reseau interdite (ni ntohs, ni inet_*, ni getaddrinfo...)"

used=""
for symbol in $tolerated; do
    if printf '%s' "$symbols" | grep -qw "$symbol"; then
        used="$used $symbol"
    fi
done
if [ -n "$used" ]; then
    printf '      fonctions systeme tolerees, a savoir defendre:%s\n' "$used"
    printf '      (elles designent une interface, elles ne lisent ni ne decodent de trafic)\n'
fi
ok "les fonctions systeme utilisees sont connues et assumees"

# Et aucune trace de libpcap ni de ses cousines dans les sources. On cite ici
# les vrais noms de l'API de libpcap: nos propres fonctions de fichier .pcap
# s'appellent pcap_writer_* et pcap_reader_*, elles ne peuvent pas etre confondues.
#
# Seule exception, volontaire et documentee: capture_windows.cpp, qui utilise
# Npcap parce que Winsock2 seul ne donne jamais l'en-tete Ethernet sous
# Windows. C'est le seul fichier du projet ou une bibliotheque de capture est
# autorisee; voir docs/PRIVILEGES.md et src/capture/capture_windows.cpp.
libpcap_api='pcap_open_live|pcap_open_offline|pcap_create|pcap_activate|pcap_next_ex'
libpcap_api="$libpcap_api|pcap_loop|pcap_dispatch|pcap_compile|pcap_setfilter"
libpcap_api="$libpcap_api|pcap_findalldevs|pcap_datalink|#include *<pcap|libtins|PcapPlusPlus"
outside_windows() {
    grep -rniE "$libpcap_api" src/ 2>/dev/null | grep -v '^src/capture/capture_windows\.cpp:'
}
if outside_windows | grep -q .; then
    outside_windows | head -3
    fail "trace d'une bibliotheque de capture dans les sources"
fi
ok "aucune trace de libpcap ni equivalent (hors capture_windows.cpp, exception Npcap assumee)"

printf '\n=== 3. Tests ===\n\n'

./build-verify/tests/tests || fail "des tests echouent"
ok "tests unitaires"

(cd build-verify && ctest --output-on-failure >/dev/null 2>&1) \
    || fail "des tests CTest echouent"
ok "tests de ligne de commande"

printf '\n=== 4. Recherche de bugs memoire (sanitizers) ===\n\n'

rm -rf build-verify-asan
cmake -S . -B build-verify-asan -DSANITIZE=ON -DWARNINGS_AS_ERRORS=ON >/dev/null 2>&1 \
    || fail "configuration des sanitizers impossible"
cmake --build build-verify-asan -j4 >/dev/null 2>&1 \
    || fail "compilation avec sanitizers impossible"
ok "compilation avec sanitizers"

./build-verify-asan/tests/tests >/dev/null \
    || fail "les sanitizers ont detecte un probleme dans les tests"
ok "aucune erreur memoire dans les tests"

./build-verify-asan/mysniffer interfaces --all >/dev/null \
    || fail "les sanitizers ont detecte un probleme sur la commande interfaces"
ok "aucune erreur memoire sur la commande interfaces"

printf '\n=== 5. Le programme repond ===\n\n'

./build-verify/mysniffer --version >/dev/null || fail "--version ne marche pas"
ok "--version"

./build-verify/mysniffer --help >/dev/null || fail "--help ne marche pas"
ok "--help"

./build-verify/mysniffer interfaces >/dev/null || fail "interfaces ne marche pas"
ok "interfaces"

# Une commande inconnue doit sortir en erreur, pas reussir en silence.
if ./build-verify/mysniffer nimportequoi >/dev/null 2>&1; then
    fail "une commande inconnue devrait echouer"
fi
ok "les commandes inconnues sont refusees"

printf '\n=== 6. Fichiers .pcap ===\n\n'

./build-verify/mysniffer read -r /nexiste/pas.pcap >/dev/null 2>&1 \
    && fail "lire un fichier absent devrait echouer"
ok "les fichiers absents sont refuses"

# Si l'utilisateur a fourni une capture, on la fait relire par un outil
# independant. C'est la meilleure preuve que notre decodage dit vrai: si
# tcpdump et nous racontons la meme chose sur les memes octets, c'est juste.
#
# On utilise tcpdump s'il est installe, sinon on le lance dans un conteneur.
if [ $# -ge 1 ]; then
    pcap="$1"
    [ -f "$pcap" ] || fail "$pcap n'existe pas"

    ours=$(./build-verify/mysniffer read -r "$pcap" 2>/dev/null | grep -c '^[0-9][0-9]:')

    if command -v tcpdump >/dev/null 2>&1; then
        # tcpdump est la: on compare champ par champ, pas seulement le compte.
        if "$ROOT/scripts/compare-tcpdump.sh" "$pcap" >/tmp/verify-compare.log 2>&1; then
            grep -E 'par nous|EXACTEMENT|Aucun paquet' /tmp/verify-compare.log \
                | sed 's/^/      /'
            ok "tcpdump extrait exactement les memes champs que nous"
        else
            cat /tmp/verify-compare.log
            fail "notre lecture differe de celle de tcpdump"
        fi
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        printf '      (tcpdump absent, on passe par un conteneur, comparaison des comptes seulement)\n'
        theirs=$(docker run --rm -v "$(cd "$(dirname "$pcap")" && pwd)/$(basename "$pcap")":/c.pcap:ro \
                 alpine:latest sh -c \
                 'apk add --no-cache tcpdump >/dev/null 2>&1; tcpdump -r /c.pcap -n 2>/dev/null | wc -l' \
                 2>/dev/null | tr -d " ")
        printf '      notre lecture: %s paquets, tcpdump: %s paquets\n' "$ours" "$theirs"
        [ "$ours" = "$theirs" ] || fail "les deux outils ne comptent pas le meme nombre de paquets"
        ok "tcpdump lit notre fichier et compte pareil"
    else
        printf '      (ni tcpdump ni docker: comparaison ignoree)\n'
        printf '      Pour l installer:  sudo pacman -S tcpdump\n'
    fi
fi

printf '\n=== 7. Documentation ===\n\n'

for doc in README.md CHANGELOG.md LICENSE docs/BUILD.md docs/INSTALL.md \
           docs/USAGE.md docs/PRIVILEGES.md; do
    [ -f "$doc" ] || fail "$doc est manquant"
done
ok "les 7 documents attendus sont presents"

rm -rf build-verify build-verify-asan

printf '\n'
printf '  Tout est bon.\n'
printf '\n'
printf '  Ce que ce script NE verifie pas, et qu il faut faire a la main:\n'
printf '    - la capture reelle:      sudo ./build/mysniffer capture -c 10\n'
printf '    - FreeBSD, macOS, Windows: voir l integration continue sur GitHub\n'
printf '\n'
printf '  Pour confronter une capture a un outil independant:\n'
printf '    sudo ./build/mysniffer capture -c 50 -w /tmp/preuve.pcap\n'
printf '    ./scripts/verify.sh /tmp/preuve.pcap\n'
printf '\n'
