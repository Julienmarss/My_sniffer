# Privileges necessaires

Lire le trafic reseau brut est une operation sensible: n'importe quel programme
qui en est capable peut voir passer les mots de passe et les donnees de tout le
monde sur le reseau local. Tous les systemes la reservent donc a l'administrateur.

Ce document explique comment lancer `mysniffer` proprement sur chaque systeme.

## Le plus simple, partout

```sh
sudo mysniffer capture
```

Ca marche sur les trois systemes. C'est la methode a utiliser pour une
demonstration ponctuelle.

L'inconvenient est que tout le programme tourne en administrateur, y compris
l'affichage et l'ecriture des fichiers. Les methodes ci-dessous sont plus
propres pour un usage regulier.

## Linux: donner une capacite au programme

Linux permet d'accorder un droit precis a un programme, au lieu de lui donner
tous les droits de l'administrateur. Celui qui nous interesse s'appelle
`cap_net_raw`: il autorise a ouvrir une socket de capture, et rien d'autre.

```sh
sudo setcap cap_net_raw+ep /usr/local/bin/mysniffer
```

Le programme se lance ensuite normalement, sans `sudo`:

```sh
mysniffer capture
```

Pour verifier:

```sh
getcap /usr/local/bin/mysniffer
```

Pour retirer le droit:

```sh
sudo setcap -r /usr/local/bin/mysniffer
```

Attention: cette permission est attachee au fichier. Elle disparait des que
le programme est recompile ou recopie, il faut alors la remettre.

## FreeBSD: autoriser un groupe sur /dev/bpf

FreeBSD passe par des fichiers speciaux, `/dev/bpf0`, `/dev/bpf1`, et ainsi de
suite. Par defaut, seul l'administrateur peut les ouvrir. On peut ouvrir ce
droit a un groupe.

Ajoutez ces deux lignes dans `/etc/devfs.conf`:

```
own     bpf*    root:network
perm    bpf*    0660
```

Puis mettez votre utilisateur dans le groupe `network` et rechargez:

```sh
sudo pw groupmod network -m votre_utilisateur
sudo service devfs restart
```

Il faut se deconnecter et se reconnecter pour que le changement de groupe
prenne effet.

## macOS: le groupe access_bpf

macOS fonctionne comme FreeBSD, mais son systeme de fichiers ne sait pas
retenir ces permissions au redemarrage. Wireshark resout ce probleme en
installant un petit service qui les repose a chaque demarrage, et qui cree
un groupe nomme `access_bpf`.

Si Wireshark est installe, il suffit de rejoindre ce groupe:

```sh
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
```

Sinon, `sudo mysniffer capture` reste la solution la plus simple.

## Windows: l installeur Npcap

Contrairement aux trois autres systemes, Windows a besoin d une bibliotheque,
Npcap, pour donner acces a la trame Ethernet brute: Winsock2 seul ne le
permet pas. C est la seule exception du projet a la regle "aucune
bibliotheque reseau", et elle ne sert qu a ouvrir la capture; le decodage
reste notre code, comme sur les trois autres systemes.
Compiler le programme demande seulement le SDK Npcap (voir docs/BUILD.md);
le FAIRE TOURNER demande en plus d installer Npcap lui-meme.

Pendant l installation, une case a cocher s appelle "Restrict Npcap driver's
access to Administrators only":

- **decochee** (par defaut): n importe quel utilisateur peut capturer, sans
  etre administrateur, ce qui correspond a l esprit du reste du projet;
- **cochee**: seul un compte administrateur peut capturer, et il faut alors
  lancer `mysniffer.exe` avec "Executer en tant qu administrateur".

Sans Npcap installe du tout, le programme affiche toujours `interfaces`
correctement (cette commande passe par une API Windows ordinaire, pas par
Npcap), mais `capture` et `analyze -i` echouent avec un message qui le dit.

## Ce que fait le programme avec ces privileges

Il les utilise uniquement pour ouvrir la capture, au tout debut. Une fois le
descripteur ouvert, plus aucune operation privilegiee n'est necessaire: lire
les paquets, les decoder et les afficher se font avec des droits ordinaires.

Le mode espion merite une remarque. Sur Linux, il est demande en faisant
adherer la socket a un groupe, et non en modifiant la configuration de la carte
reseau. La difference compte: le noyau annule cette adhesion tout seul quand le
programme s'arrete, meme s'il plante. En modifiant la carte, elle resterait en
mode espion apres coup, sans que personne s'en apercoive.

## En cas de refus

Le message d'erreur ressemble a ceci:

```
erreur: impossible d'ouvrir la socket de capture: Operation not permitted
```

Cela veut dire que le programme n'a pas les droits. Relisez la section qui
correspond a votre systeme.
