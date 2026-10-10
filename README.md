# My_sniffer

Un analyseur de paquets reseau ecrit de zero en C++, pour Linux, FreeBSD et macOS.

Aucune bibliotheque reseau n'est utilisee. La capture, la lecture et le decodage des
paquets sont ecrits entierement a la main, comme le sujet l'exige. Le projet n'a
d'ailleurs aucune dependance externe: il suffit d'un compilateur et de CMake.

## Etat

En cours de developpement. La version actuelle capture le trafic, decode Ethernet, IPv4, TCP et UDP, et
sait lire et ecrire des fichiers `.pcap` que Wireshark relit sans probleme,
filtre les paquets selon des regles, et detecte les comportements anormaux.
Voir [CHANGELOG.md](CHANGELOG.md).

## Compiler et lancer

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Le programme est alors dans `build/mysniffer`.

```sh
./build/mysniffer --help
./build/mysniffer interfaces
sudo ./build/mysniffer capture -c 10
```

La capture demande des privileges. Les differentes facons de les accorder
proprement sont dans [docs/PRIVILEGES.md](docs/PRIVILEGES.md).

| Document | Contenu |
|---|---|
| [docs/BUILD.md](docs/BUILD.md) | compiler, par systeme |
| [docs/INSTALL.md](docs/INSTALL.md) | installer |
| [docs/USAGE.md](docs/USAGE.md) | mode d'emploi des commandes |
| [docs/PRIVILEGES.md](docs/PRIVILEGES.md) | pourquoi et comment accorder les droits |


## Verifier que tout va bien

```sh
./scripts/verify.sh
```

Le script compile avec les warnings traites comme des erreurs, lance les tests,
les rejoue sous les detecteurs de bugs memoire, et verifie la documentation.
Il s'arrete au premier probleme en disant lequel.

Pour aller plus loin, donnez-lui une capture: il la fera relire par `tcpdump`,
un outil qui ne partage aucune ligne de code avec le notre, et comparera les
heures, les adresses et les ports extraits de chaque paquet.

```sh
sudo ./build/mysniffer capture -c 50 -w /tmp/preuve.pcap
./scripts/verify.sh /tmp/preuve.pcap
```

La comparaison seule, avec le detail des differences s'il y en a:

```sh
./scripts/compare-tcpdump.sh /tmp/preuve.pcap
```

Si `tcpdump` n'est pas installe (`sudo pacman -S tcpdump`), le script se rabat
sur un conteneur Docker et compare seulement le nombre de paquets.

Preparation a la soutenance, chaque point en deux ou trois phrases:
[docs/defense/ORAL.md](docs/defense/ORAL.md).

Comment tout le projet fonctionne, explique simplement:
[docs/defense/COMMENT-CA-MARCHE.md](docs/defense/COMMENT-CA-MARCHE.md).

L etat du projet face au sujet, point par point, est dans
[docs/defense/CONFORMITE.md](docs/defense/CONFORMITE.md).

## Organisation du code

| Dossier | Contenu | Depend de |
|---|---|---|
| `src/net/` | Types et calculs purs: octets, adresses MAC, adresses IPv4, sommes de controle | rien |
| `src/dissect/` | Decodage des protocoles, un fichier par protocole | `net` |
| `src/capture/` | Cartes reseau et capture, un fichier par systeme | `net` |
| `src/storage/` | Lecture et ecriture des fichiers `.pcap` | `net` |
| `src/filter/` | Langage de filtrage des paquets | `dissect` |
| `src/analysis/` | Detection de comportements anormaux | `dissect` |
| `src/log/` | Journal d'execution | rien |
| `src/cli/` | La ligne de commande | tout |
| `tests/` | Les tests, un fichier par module | tout |
| `docs/` | Documentation, sujet, et sources de soutenance | |

Les dependances vont toujours dans le meme sens, de la ligne de commande vers
`net`, jamais l'inverse. Aucun module ne connait celui qui l'utilise.

## Plateformes

| Systeme | Methode de capture |
|---|---|
| Linux | socket `AF_PACKET` |
| FreeBSD | peripherique `bpf` |
| macOS | peripherique `bpf`, le meme que FreeBSD |
| Windows | Npcap |

Windows est la seule exception a la regle "aucune bibliotheque reseau": Winsock2
seul n'y donne jamais l'en-tete Ethernet. Npcap sert uniquement a ouvrir la
capture; le decodage reste notre code partout. Voir [docs/PRIVILEGES.md](docs/PRIVILEGES.md).

## Licence

MIT. Voir [LICENSE](LICENSE).
