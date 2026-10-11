# Conformite au sujet

Cette fiche reprend le sujet phrase par phrase et dit, pour chacune, ou en est
le projet et comment le prouver. Elle sert a deux choses: savoir ou on va, et
preparer les questions du jury.

Derniere mise a jour: 10 octobre 2026.

> **Depot commite, pousse et etiquete `v1.0.0`.** Le point qui primait sur tous
> les autres (aucun commit, rien d'evalue) est resolu. Ce qui reste prioritaire
> maintenant: confirmer une vraie capture sur macOS (la CI vient d'etre
> declenchee par ce push, a verifier) et sur Windows (a tester dans une VM,
> aucune CI ne peut le prouver sans y installer Npcap a la main).

Legende: **fait** / **partiel** / **a faire**

---

## Consignes generales

| Consigne | Etat | Preuve |
|---|---|---|
| Ecrit en C ou C++ | fait | C++17, `CMakeLists.txt` |
| Aucune bibliotheque reseau, ni capture, ni analyse, ni decodage | fait | `grep -r pcap src/` ne renvoie rien. Aucun `#include <arpa/inet.h>`, aucun `ntohs`. Voir la fonction `to_network_order` dans `capture_linux.cpp`: on refait meme `htons` a la main. |
| Bibliotheques non reseau autorisees | fait | On n'en utilise aucune. Zero dependance. |
| Compile sans erreur ni warning | fait | `./scripts/verify.sh` echoue au moindre warning |
| Aucun plantage | fait | Sanitizers sur toute la suite de tests, et chaque paquet de test est coupe a toutes les positions possibles |
| Systeme de compilation au choix, avec tout ce qu'il faut pour compiler, installer et lancer | fait | CMake, cible d'installation, `docs/BUILD.md` et `docs/INSTALL.md` |
| C'est un produit, pas un devoir | fait | Documentation, changelog, tests, etiquette `v1.0.0`, scripts d'installation par plateforme (Linux, FreeBSD, macOS; Windows passe par l'installeur Npcap) |
| Documenter les privileges necessaires | fait | `docs/PRIVILEGES.md`, une section par systeme |

---

## Partie obligatoire

### Etape 0, fonctions de conversion binaire

**Etat: fait.**

| Ou | Quoi |
|---|---|
| `src/net/bytes.cpp` | lecture des entiers en big-endian, avec verification de taille |
| `src/net/mac.cpp` | adresses physiques: lecture, affichage, broadcast, multicast |
| `src/net/ipv4_address.cpp` | adresses IPv4: lecture, affichage, classification, masques |
| `src/net/checksum.cpp` | somme de controle Internet (RFC 1071) et pseudo en-tete |

Comment le prouver: `./build/tests/tests` affiche le detail par module.

### Etape 1, visualiseur de paquets

**Etat: fait et prouve sous Linux. Ecrit et compile pour FreeBSD, macOS et
Windows; capture reelle pas encore confirmee sur ces trois-la.**

| Exigence | Etat |
|---|---|
| Capturer tous les paquets de son interface | fait, `src/capture/capture_linux.cpp` |
| Multiplateforme, Linux plus un autre systeme | fait x4: Linux prouve; `capture_bsd.cpp` (FreeBSD/macOS) et `capture_windows.cpp` compilent, capture reelle a confirmer |
| Ethernet | fait, etiquettes VLAN empilees comprises |
| IPv4 | fait, somme de controle verifiee, fragments detectes |
| TCP | fait, les neuf drapeaux dont ECE, CWR et AE |
| UDP | fait, somme facultative geree |

Comment le prouver: `sudo ./build/mysniffer capture -c 10`.

Ce qui reste a faire: verifier l'etape "Capture reelle" du job macOS dans la
CI GitHub (declenchee par le dernier push), et tester une vraie capture
Windows dans une VM (Npcap ne peut pas s'installer silencieusement en CI).

### Etape 2, filtrage et recherche

**Etat: fait.**

Un langage de regles avec son propre analyseur, dans `src/filter/`. La syntaxe
ressemble a celle de tcpdump parce qu'elle est connue, mais l'analyse du texte
et l'evaluation sont entierement ecrites ici.

| Ce qu'on peut ecrire | Exemple |
|---|---|
| protocole | `tcp`, `udp`, `icmp`, `arp`, `ip`, `ip6`, `vlan`, `eth` |
| adresse | `host 8.8.8.8`, `src host 192.168.1.1` |
| reseau | `net 192.168.0.0/16` |
| port | `port 443`, `dst port 53`, `portrange 8000-8100` |
| drapeaux TCP | `tcp-flags syn`, `tcp-flags syn,ack` |
| taille | `len > 1000` |
| combinaisons | `and`, `or`, `not`, parentheses |

Comment le prouver: `./build/mysniffer read -r capture.pcap -f "tcp and port 443"`,
et la meme regle donnee a `tcpdump` doit rendre le meme nombre de paquets.
Verifie sur 15 regles differentes: resultats identiques.

Depuis que ARP est decode (voir Partie bonus), `host` et `net` regardent
aussi les adresses a l'interieur des trames ARP, comme chez tcpdump.

### Etape 3, analyse des comportements anormaux

**Etat: fait.**

Six detecteurs dans `src/analysis/`, un par comportement cite par le sujet.
La collecte remplit des compteurs, le verdict est rendu a la fin.

| Comportement demande | Comment on le detecte |
|---|---|
| beaucoup de requetes vers un service | compteur par couple adresse et port |
| beaucoup d'erreurs en retour | compteur de paquets RST par service emetteur |
| pics de trafic | paquets par seconde compares a la moyenne |
| connexions vers des adresses etrangeres | adresses publiques contactees, triees par volume |
| protocole inattendu sur un port standard | signature du debut des donnees sur les ports 80, 443 et 22 |
| intervalles reguliers | ecart moyen des intervalles a leur moyenne |

Comment le prouver: `./build/mysniffer analyze -r capture.pcap`. Une capture
fabriquee avec les six comportements les declenche tous les six; une capture
ordinaire n'en declenche aucun.

Trois reglages viennent de l'epreuve du trafic reel, et chacun a supprime une
classe de fausses alertes:

- les balises ne sont signalees que vers l'exterieur, car dans un reseau local
  la regularite est la norme;
- et au-dela de 10 secondes d'intervalle, car une connexion active envoie un
  paquet par seconde sans etre une balise;
- le detecteur de requetes compare un DEBIT et non un nombre total, mesure sur
  la fenetre propre a chaque service. Sans cela, chaque site web visite
  declenchait une alerte.

L'option `--allow` permet de declarer connus les reseaux legitimes. Sans elle,
le programme ne peut pas parler de connexion "non autorisee" comme le demande le
sujet: il ne saurait qu'inventorier. Mesure sur dix minutes de navigation
ordinaire: sept fausses alertes avant ces corrections, zero apres.

### Etape 4, empaquetage et deploiement

**Etat: fait.**

| Exigence | Etat |
|---|---|
| Systeme de compilation avec une cible d'installation | fait, `cmake --install` |
| Scripts de compilation et d'installation par plateforme | fait: `scripts/install-linux.sh`, `install-freebsd.sh`, `install-macos.sh`; Windows passe par l'installeur Npcap lui-meme |
| Versionnage des livraisons (etiquettes, changelog) | fait: commit, etiquette `v1.0.0`, `CHANGELOG.md` tenu a jour |
| Documentation: compiler, installer, lancer, privileges | fait, quatre documents |

---

## Ce que le sujet demande de prendre en charge

| Element | Etat |
|---|---|
| Modules de capture, multiplateformes | fait pour 4 systemes; Linux prouve, FreeBSD/macOS/Windows compilent, capture reelle a confirmer |
| Decodage des paquets | fait |
| Filtrage | fait |
| Analyse | fait |
| Journalisation et stockage | fait: stockage `.pcap` et journal d'execution separe du resultat |
| Compilation, empaquetage, deploiement | fait |

Sur la journalisation: `src/log/` tient un journal avec quatre niveaux de
gravite, dirigeable vers un fichier. Il est volontairement separe du resultat:
les paquets et les alertes vont sur la sortie standard, le journal sur la
sortie d'erreur. On peut donc rediriger le resultat dans un fichier sans que
les messages de service viennent le salir.

---

## Partie bonus

Le sujet est formel: le bonus n'est evalue que si la partie obligatoire est
parfaite. Rien de tout ceci ne doit etre commence avant.

| Bonus | Etat |
|---|---|
| ARP | fait: `src/dissect/arp.cpp`, requete/reponse, `host`/`net` les voient aussi |
| ICMP | fait: `src/dissect/icmp.cpp`, type/code/somme, identifiant+sequence pour l'echo |
| IPv6, DNS, HTTP | a faire. IPv6 est deja reconnu (ethertype), mais pas decode. |
| Detection d'un autre analyseur sur le reseau | a faire, deja etudiee (notes personnelles) |
| Interface graphique ou texte | fait: `src/gui/server.cpp`, page web locale (boutons -> vraies commandes). Linux uniquement, voir plus bas |

### Lancer l'interface web

Compile uniquement sous Linux (`CMakeLists.txt` l'exclut ailleurs: outil de
demonstration pour cette machine, pas un livrable multiplateforme).

```sh
sudo ./build/mysniffer-gui
```

`sudo` est necessaire pour que les boutons de capture en direct marchent
(memes privileges que `sudo ./build/mysniffer capture`). Puis ouvrir
`http://127.0.0.1:7878` dans un navigateur. Sept boutons, chacun lance une
vraie commande et affiche son resultat tel quel: version, interfaces, capture
en direct, filtrage, ecriture+relecture d'un `.pcap`, analyse comportementale,
et un bonus ARP+ICMP (lit un fichier `.pcap` prepare a l'avance, pour ne pas
dependre d'une vraie trame ARP qui passerait au bon moment pendant l'oral).

Aucune commande n'est jamais construite a partir de ce que le navigateur
envoie: chaque bouton correspond a une commande ecrite a l'avance dans
`ACTIONS`, le navigateur ne fait que choisir laquelle.

---

## Comment tout verifier soi-meme

```sh
./scripts/verify.sh                      # compilation, tests, sanitizers, documentation
sudo ./build/mysniffer capture -c 10     # la capture reelle
```

Puis la preuve la plus solide, celle qui ne repose pas sur notre propre code:

```sh
sudo ./build/mysniffer capture -c 50 -w /tmp/preuve.pcap
./scripts/compare-tcpdump.sh /tmp/preuve.pcap
```

Le script extrait de chaque paquet l'heure, les adresses et les ports, avec
notre programme d'un cote et `tcpdump` de l'autre, et met les deux en face.
Verifie sur une capture reelle de 50 paquets et sur huit fichiers du projet
tcpdump, dont plusieurs volontairement casses: aucune difference.

Pour l'inspection a l'oeil, avec les outils de reference (a installer avec
`sudo pacman -S tcpdump wireshark-qt`):

```sh
tcpdump -r /tmp/preuve.pcap      # doit lire le fichier sans broncher
wireshark /tmp/preuve.pcap       # doit afficher les memes paquets
./build/mysniffer read -r /tmp/preuve.pcap
```

Les trois lectures doivent raconter la meme histoire: memes heures, memes
adresses, memes ports, memes tailles.
