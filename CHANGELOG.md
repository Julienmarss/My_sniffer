# Changelog

Toutes les modifications notables de ce projet sont listees ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et le projet suit le [versionnage semantique](https://semver.org/lang/fr/).

## [1.1.0] - 2026-10-10

### Ajoute

- Bonus: interface web locale (`src/gui/server.cpp`, cible `mysniffer-gui`).
  Serveur HTTP minimal fait maison (sockets ordinaires, zero dependance,
  ordre des octets reseau recompose a la main comme ailleurs dans le
  projet), une page avec sept boutons qui lancent de vraies commandes et
  affichent le resultat tel quel. Compile uniquement sous Linux: outil de
  demonstration pour cette machine, pas un livrable multiplateforme.
  Un fichier `.pcap` ARP+ICMP+TCP est embarque pour que le bouton bonus
  marche sans dependre d'un vrai trafic au bon moment pendant l'oral.
  Protege par un jeton tire au hasard a chaque lancement (une page ouverte
  dans un autre onglet ne peut pas declencher une capture a notre insu), par
  la verification de l'en-tete `Host` sur chaque requete (empeche qu'une page
  attaquante fasse pointer son propre nom de domaine vers 127.0.0.1 apres
  coup pour se faire passer pour ce serveur et lire le jeton dans la page),
  et par un dossier temporaire prive cree a chaque demarrage (`mkdtemp`,
  droits 0700) au lieu de chemins fixes dans `/tmp`, partage par tout le
  monde et donc piegeable par un lien symbolique pose a l'avance.

## [1.0.3] - 2026-10-10

### Corrige

- `tests/test_iface.cpp` supposait que la boucle locale s'appelle "lo" ou
  "lo0": vrai sur Linux/BSD/macOS, faux sous Windows (un GUID). Cette
  verification de nom precis contredisait d'ailleurs le commentaire en tete
  de fichier, qui annonce ne tester que des proprietes valables partout.
  Retiree; `is_loopback` et `interface_is_capturable() == false` suffisent
  a prouver que la boucle locale est bien reconnue et exclue de la capture.

## [1.0.2] - 2026-10-10

### Corrige

- `tests/test_pcap.cpp` et `tests/test_log.cpp` ne compilaient pas sous
  Windows: `<unistd.h>` n'existe pas sur ce systeme, et les chemins codes en
  dur `/tmp/...` n'y sont pas valides. Remplace `unlink()` par `remove()`
  (standard C, deja inclus via `<stdio.h>`) et les chemins absolus par des
  noms de fichiers relatifs au dossier d'execution des tests, qui marchent
  identiquement sur les quatre systemes sans code specifique a l'un d'eux.

## [1.0.1] - 2026-10-10

### Corrige

- Compilation Windows cassee par `__attribute__((format(printf, ...)))` dans
  `log.hpp`: cette syntaxe est propre a GCC et Clang, MSVC refusait de
  compiler. Neutralisee sur les autres compilateurs par une macro.
- Mode espion refuse sans recours sur certaines interfaces qui ne le gerent
  pas du tout (observe sur `anpi0`, une pseudo-interface interne de macOS,
  via la CI): `capture_bsd.cpp` continue maintenant sans mode espion dans ce
  cas precis (erreur systeme ENOTSUP), au lieu de refuser toute capture.
  Le programme dit desormais honnetement si le mode espion demande n'a pas
  pu etre obtenu, au lieu de pretendre qu'il l'a ete.

## [1.0.0] - 2026-10-10

### Ajoute

- Affichage en couleur, et alignement des colonnes. Les adresses, protocoles,
  drapeaux et tailles tombent desormais toujours au meme endroit, ce qui
  rend une capture de plusieurs centaines de lignes lisible d'un coup d'oeil.
- Option `--color auto|always|never`. Par defaut la couleur n'apparait que si
  la sortie est un terminal: rediriger vers un fichier ou vers `grep` donne du
  texte brut, sans codes parasites. La variable d'environnement `NO_COLOR` et
  un terminal `TERM=dumb` coupent aussi la couleur.

### Corrige

- Ctrl+C ne fonctionnait pas sur une interface sans trafic: le gestionnaire
  etait pose avec `signal()`, qui fait redemarrer la lecture bloquante. Corrige
  avec `sigaction()`.
- Un paquet coupe par la capture etait signale comme ayant une somme de
  controle fausse, alors qu'elle est simplement invérifiable. Le garde-fou
  testait une valeur deja rabotee, donc toujours vraie.

### Modifie

- Architecture des fichiers: `net` ne depend de rien, `dissect`, `capture` et
  `storage` ne dependent que de `net`, `cli` connait tout. Plus aucun cycle,
  et deux fichiers ne portent plus le meme nom.
- Les fonctions de fichier `.pcap` s'appellent `pcap_writer_*` et
  `pcap_reader_*`, pour qu'on ne les confonde pas avec libpcap.
- La ligne de commande est decoupee: `cli/main.cpp` aiguille, `cli/commands.cpp`
  travaille. La plus longue fonction passe de 113 a 45 lignes.
- Messages d'erreur uniformes, et une option sans valeur le dit clairement.
- `verify.sh` prouve automatiquement qu'aucune bibliotheque reseau n'est liee
  ni aucune fonction reseau de la libc utilisee.

### Ajoute

- Moteur d'analyse des comportements anormaux, avec les six detecteurs cites
  par le sujet: requetes massives vers un service, refus en serie, pics de
  trafic, connexions vers des adresses publiques, protocole inattendu sur un
  port standard, et appels a intervalle regulier. Commande `mysniffer analyze`.
- Journal d'execution, separe du resultat: niveaux debug/info/warn/error,
  options `-v`, `--log-level` et `--log-file`.

- Seuils d'analyse reglables en ligne de commande, et option `--allow` pour
  declarer connus les reseaux legitimes.
- Langage de filtrage, avec son propre analyseur: protocoles, adresses,
  reseaux, ports, intervalles de ports, drapeaux TCP, taille, et les
  operateurs `and`, `or`, `not` avec parentheses. Option `-f` sur les
  commandes `capture` et `read`.
- Le decodage d'un paquet est rassemble en un seul endroit, `decode_packet`,
  dont se servent l'affichage et le filtre. Un paquet n'est decode qu'une fois.
- Lecture d'une adresse IPv4 ecrite en texte, et comparaison d'adresses.

- Systeme de compilation CMake, avec options pour les warnings en erreurs
  et pour les sanitizers.
- Lecture des nombres dans un paquet, en big-endian, avec verification de taille.
- Adresses MAC: lecture, affichage, detection broadcast et multicast.
- Adresses IPv4: lecture, affichage, classification (privee, boucle locale,
  lien local, multicast) et conversion d'un masque en longueur de prefixe.
- Liste des cartes reseau du systeme, sur Linux et sur la famille BSD.
- Commande `mysniffer interfaces`, avec l'option `--all`.
- Somme de controle Internet (RFC 1071), et le pseudo en-tete de TCP et UDP.
- Decodage Ethernet, avec les etiquettes VLAN.
- Decodage IPv4: tous les champs, verification de la somme, detection des fragments.
- Decodage TCP: ports, numeros de sequence, drapeaux, verification de la somme.
- Decodage UDP: ports, longueur, somme facultative.
- Capture reelle: socket `AF_PACKET` sous Linux, peripherique `bpf` sous FreeBSD et macOS,
  Npcap sous Windows (seule bibliotheque du projet, limitee a l'ouverture de la capture;
  le decodage reste notre code sur les quatre systemes).
- Liste des interfaces sous Windows via `GetAdaptersAddresses`, sans avoir besoin de Npcap.
- Decodage ARP (bonus): requete et reponse, adresses materielle et IP des deux
  cotes. `host` et `net` regardent aussi ces adresses, comme chez tcpdump.
- Decodage ICMP (bonus): type, code, somme de controle, et l'identifiant plus
  le numero de sequence pour l'echo (requete/reponse "ping").
- Commande `mysniffer capture`, avec les options `-i`, `-c` et `-p`.
- Arret propre sur Ctrl+C, avec le nombre de paquets perdus par le systeme.
- Reconnaissance du calcul de somme delegue a la carte reseau, pour ne pas
  signaler a tort les paquets emis par la machine.
- Tests sans aucune bibliotheque externe. Le decodage est verifie sur de vrais
  paquets, et teste tronque a chaque position possible.
- Fichier d'integration continue pour Linux, FreeBSD, macOS et Windows, avec
  les sanitizers sur Linux.
- Documentation des privileges necessaires par systeme.
- Lecture et ecriture de fichiers `.pcap`, le format de tcpdump et Wireshark.
  Les deux ordres d'octets et les dates en nanosecondes sont geres a la lecture.
- Option `-w` pour enregistrer une capture, commande `read` pour la relire.
- Drapeaux TCP de controle de congestion: ECE, CWR, et AE (l'ancien bit NS,
  reattribue par l'IANA en 2026).
- Etiquettes VLAN empilees (QinQ), reconnues sous leurs deux numeros.
- Signalement des en-tetes IPv4 qui annoncent plus d'octets que la trame
  n'en contient.
- Documentation d'installation et mode d'emploi.
- Noms lisibles pour les protocoles IP courants: IGMP, GRE, ESP, AH, OSPF, SCTP.
- Script `scripts/verify.sh`: compile, teste, cherche les bugs memoire, et
  confronte une capture a `tcpdump`.
- Script `scripts/compare-tcpdump.sh`: compare notre lecture d'une capture a
  celle de `tcpdump`, heure par heure et champ par champ.
- Fiche de conformite au sujet dans `docs/defense/CONFORMITE.md`.
- Reconnaissance des paquets assembles par la carte reseau, dans les deux sens.
  Un paquet plus gros qu'une trame Ethernet est signale comme tel, et sa somme
  de controle n'est plus presentee comme fausse.
- La relecture d'un fichier compare les adresses aux cartes de la machine, pour
  dire la meme chose que la capture en direct quand le fichier vient d'ici.
