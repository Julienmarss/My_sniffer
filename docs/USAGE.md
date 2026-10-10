# Mode d'emploi

## Les quatre commandes

```sh
mysniffer interfaces          # quelles cartes reseau sont disponibles
mysniffer capture             # regarder le trafic passer en direct
mysniffer read -r fichier     # relire une capture enregistree
mysniffer analyze -r fichier  # chercher les comportements anormaux
```

Chaque commande accepte `--help` sur le programme pour rappeler ses options.

## Lister les cartes reseau

```sh
mysniffer interfaces
```

```
NOM              INDEX  MAC                ETAT                  ADRESSES
wlo1                 2  c8:5e:a9:53:40:3a  up running            172.30.0.86/20
docker0              8  3e:90:af:8b:bf:0c  up                    172.17.0.1/16
```

Par defaut, seules les cartes utilisables pour capturer sont montrees. Ajoutez
`--all` pour voir aussi la boucle locale et les interfaces desactivees.

Cette commande ne demande aucun privilege.

## Capturer en direct

```sh
sudo mysniffer capture
```

Sans autre option, le programme choisit tout seul une carte active et affiche
les paquets jusqu'a ce que vous fassiez Ctrl+C.

| Option | Effet |
|---|---|
| `-i wlo1` | ecouter sur cette carte precise |
| `-c 100` | s'arreter apres 100 paquets |
| `-p` | ne pas activer le mode espion |
| `-w sortie.pcap` | enregistrer au lieu d'afficher |
| `-f "tcp and port 80"` | ne garder que les paquets qui suivent la regle |

Une ligne de sortie se lit ainsi:

```
00:55:14.254505  b4:7a:f1:86:73:64 > c8:5e:a9:53:40:3a  162.159.136.234:443 > 172.30.0.86:55716  TCP  ACK, PSH  97 octets
```

| Partie | Signification |
|---|---|
| `00:55:14.254505` | heure de capture, a la microseconde |
| `b4:7a:... > c8:5e:...` | adresse physique de l'emetteur, puis du destinataire |
| `162.159.136.234:443 > 172.30.0.86:55716` | adresse et port IP, source puis destination |
| `TCP` | protocole de transport |
| `ACK, PSH` | drapeaux TCP actifs |
| `97 octets` | taille des donnees transportees |

Le mode espion fait accepter a la carte les trames qui ne lui sont pas
destinees. Sans lui, vous ne voyez que le trafic de votre propre machine.
Sur un reseau moderne, il montre surtout le trafic de diffusion: les
commutateurs n'envoient plus tout a tout le monde.

## Filtrer

Sans regle, tous les paquets passent. Avec `-f`, seuls ceux qui repondent a la
regle sont gardes, aussi bien en direct qu'en relisant un fichier.

```sh
sudo mysniffer capture -f "tcp and dst port 443"
mysniffer read -r seance.pcap -f "udp or arp"
```

### Les briques d'une regle

| Ce qu'on ecrit | Ce que ca garde |
|---|---|
| `tcp` `udp` `icmp` `arp` `ip` `ip6` `vlan` `eth` | les paquets de ce protocole |
| `host 8.8.8.8` | tout ce qui parle a cette machine |
| `net 192.168.0.0/16` | tout un reseau |
| `port 443` | tout ce qui touche a ce port |
| `portrange 8000-8100` | un intervalle de ports |
| `tcp-flags syn` ou `tcp-flags syn,ack` | les paquets qui portent ces drapeaux |
| `len > 1000` | selon la taille de la trame |

### Preciser un cote

`src` et `dst` limitent la regle a l'emetteur ou au destinataire.

```sh
mysniffer read -r x.pcap -f "dst port 53"       # les requetes vers un DNS
mysniffer read -r x.pcap -f "src host 8.8.8.8"  # ce qui vient de cette machine
```

Sans precision, les deux cotes conviennent.

### Combiner

`and`, `or`, `not`, et des parentheses. `and` se lie plus fort que `or`, donc
`udp or tcp and port 80` se lit `udp or (tcp and port 80)`.

```sh
mysniffer read -r x.pcap -f "tcp and not port 443"
mysniffer read -r x.pcap -f "(udp or icmp) and net 10.0.0.0/8"
mysniffer read -r x.pcap -f "tcp-flags syn and not tcp-flags ack"
```

La derniere regle est utile: elle montre les debuts de connexion, donc qui
essaie de se connecter a quoi.

### Ce que dit le bilan

Avec un filtre, la derniere ligne compte les deux:

```
2 paquet(s) lu(s) sur 50 examine(s).
```

### Une difference avec tcpdump

Chez tcpdump, `host` et `net` regardent aussi les adresses ecrites a
l'interieur des trames ARP. Nous ne decodons pas encore ARP, qui releve du
bonus, donc nos regles d'adresse ne voient que les paquets IPv4. Sur une
capture ordinaire, l'ecart se limite aux quelques trames ARP du reseau local.

## Enregistrer et relire

```sh
sudo mysniffer capture -c 500 -w seance.pcap
mysniffer read -r seance.pcap
```

Le fichier produit est au format `.pcap`, celui de tcpdump et de Wireshark.
Vous pouvez donc l'ouvrir avec eux:

```sh
wireshark seance.pcap
tcpdump -r seance.pcap
```

Et inversement, `mysniffer read` accepte les fichiers produits par ces outils.

La relecture ne demande aucun privilege: c'est la facon commode de travailler
sur une capture sans rester administrateur.

## Chercher les comportements anormaux

```sh
mysniffer analyze -r seance.pcap      # sur un fichier, sans privileges
sudo mysniffer analyze -i wlo1        # en direct
```

Le programme compte, puis rend son verdict a la fin. Six comportements sont
cherches: trop de requetes vers un service, trop d'erreurs en retour, un pic
de trafic, une connexion vers une adresse publique non declaree, un protocole
inattendu sur un port standard, et des intervalles reguliers (une balise).

| Option | Effet |
|---|---|
| `--allow 8.8.8.0/24` | declarer un reseau connu, repetable |
| `--max-requests N` | nombre de paquets avant de s'interesser a un service |
| `--max-rate N` | paquets par seconde au-dela desquels on signale |
| `--max-errors N` | refus de connexion avant de signaler un service |
| `--spike-factor N` | une seconde est un pic au-dela de N fois la moyenne |
| `--beacon-interval N` | intervalle minimal, en secondes, d'une balise |

`--allow` est la plus utile. Sans elle, le programme signale toutes les adresses
publiques contactees, ce qui est un inventaire et non une detection. En declarant
les reseaux que vous connaissez, il ne reste que ce que vous ne savez pas
expliquer.

```sh
mysniffer analyze -r seance.pcap --allow 142.250.0.0/16 --allow 17.253.0.0/16
```

## Le journal

Le journal raconte la vie du programme et va sur la sortie d'erreur, separement
du resultat qui va sur la sortie standard.

```sh
mysniffer read -r x.pcap --log-file journal.txt -v > resultat.txt
```

| Option | Effet |
|---|---|
| `-v`, `-vv` | journal plus bavard |
| `--log-level L` | debug, info, warn (defaut) ou error |
| `--log-file F` | ecrire dans F plutot que sur la sortie d'erreur |

Sous `sudo`, choisissez un chemin hors de `/tmp`: le noyau refuse qu'un
programme administrateur ecrive dans un fichier qui ne lui appartient pas au
milieu d'un dossier partage.

## L'affichage

Chaque paquet tient sur une ligne, en colonnes fixes:

```
heure            adresses MAC                           adresses IP et ports                        proto drapeaux    taille    annotations
22:33:20.120000  c8:5e:a9:53:40:3a > 70:69:5a:39:10:48  10.116.120.115:54321  > 93.184.216.34:80    TCP   SYN            0 octets
22:33:20.147462  c8:5e:a9:53:40:3a > 70:69:5a:39:10:48  10.116.120.115:41072  > 160.79.104.10:443   TCP   ACK, PSH     517 octets
22:33:20.174924  c8:5e:a9:53:40:3a > 70:69:5a:39:10:48  10.116.120.115:51234  > 8.8.8.8:53          UDP                  33 octets
```

Les champs sont completes avec des espaces pour tomber toujours a la meme
colonne, et la taille est alignee a droite: sur des centaines de lignes, l'oeil
peut descendre une colonne sans la perdre.

La couleur distingue les roles, pas les protocoles:

| Couleur | Ce qu'elle marque |
|---|---|
| gris | l'heure, les adresses MAC, les annotations qui EXPLIQUENT quelque chose de normal |
| cyan | les adresses IP et les ports |
| jaune | le protocole |
| magenta | les drapeaux TCP |
| rouge | ce qui ne va pas: somme fausse, paquets perdus, alertes de l'analyse |

| Option | Effet |
|---|---|
| `--color auto` | defaut: couleur seulement si la sortie est un terminal |
| `--color always` | couleur meme vers un fichier, pour `less -R` |
| `--color never` | jamais de couleur |

Par defaut, rediriger la sortie donne donc du texte brut:

```sh
mysniffer read -r x.pcap > sortie.txt      # sans aucun code de couleur
mysniffer read -r x.pcap | grep 443        # grep voit du texte propre
mysniffer read -r x.pcap --color always | less -R
```

La variable d'environnement `NO_COLOR` ([convention partagee entre
outils](https://no-color.org/)) et un terminal `TERM=dumb` coupent aussi la
couleur, sans rien avoir a taper.

## Les annotations entre crochets

| Annotation | Ce qu'elle veut dire |
|---|---|
| `[somme calculee par la carte]` | Le paquet vient de cette machine. Sa somme de controle sera remplie par la carte reseau juste avant l'envoi, donc apres notre capture. C'est normal. |
| `[assemble par la carte a partir de plusieurs trames, somme perdue]` | Le paquet est plus gros qu'une trame Ethernet. La carte en a fusionne plusieurs a la reception. Sa somme de controle n'a plus de sens. |
| `[somme TCP invalide]` | La somme ne tombe pas juste, sans explication connue. C'est le seul cas ou une vraie corruption est possible, et elle reste rare. |
| `[longueur IP annoncee superieure a la trame]` | L'en-tete annonce plus d'octets que la trame n'en contient. Soit la capture a coupe, soit le paquet est incoherent. |
| `[tronque, N sur le cable]` | Le paquet mesurait N octets, on n'en a garde qu'une partie. |
| `[fragment, decalage N]` | Le paquet a ete coupe en morceaux par le reseau. Seul le premier morceau porte l'en-tete TCP ou UDP; celui-ci commence N octets plus loin. |
| `[en-tete TCP invalide]` | Le paquet se dit TCP mais son en-tete est inutilisable: trop court, ou annonce une taille impossible. |

## Questions frequentes

**Je ne vois que mes propres paquets.** C'est normal sur un reseau commute.
Le mode espion ne suffit pas: le commutateur ne vous envoie que ce qui vous
concerne. Pour voir davantage, il faut un port miroir ou un concentrateur.

**Je vois passer des paquets de 7240 octets.** Ils depassent la taille maximale
d'une trame Ethernet, et c'est normal: la carte les decoupera elle-meme. On les
capture avant ce decoupage.

**La capture refuse de demarrer.** Il manque les privileges.
Voir [PRIVILEGES.md](PRIVILEGES.md).
