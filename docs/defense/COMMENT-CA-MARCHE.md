# Comment ca marche, explique simplement

Ce document explique le projet sans jargon. Il sert a le comprendre, et a le
raconter a quelqu'un qui ne connait pas.

---

## 1. L'idee en une image

Imagine un colis livre chez toi. Il a plusieurs emballages, l'un dans l'autre,
et chaque emballage porte une etiquette differente.

| Emballage | Ce que dit son etiquette | Le vrai nom |
|---|---|---|
| Le plus a l'exterieur | De quelle **boite aux lettres** a quelle boite aux lettres, dans la rue | Ethernet |
| Celui du dessous | De quelle **maison** a quelle maison, dans le monde entier | IP |
| Encore dessous | Pour quelle **personne** dans la maison | TCP ou UDP |
| Au centre | Le contenu du colis | les donnees |

Sur un reseau, c'est exactement pareil. Chaque paquet qui circule porte trois
etiquettes empilees, puis les vraies donnees.

**Ton programme est celui qui ouvre les emballages et lit les etiquettes a voix
haute.** C'est tout. Le reste n'est la que pour le faire proprement.

Un exemple de ce qu'il dit sur un paquet:

```
02:03:21.181083  c8:5e:a9:53:40:3a > b4:7a:f1:86:73:64  172.30.0.86:58760 > 89.27.238.3:443  TCP  ACK  0 octets
```

Traduction:
- **à 2h03**, un paquet est passe;
- de la **carte reseau** `c8:5e...` vers la carte `b4:7a...` (premiere etiquette);
- de la **machine** `172.30.0.86` vers la machine `89.27.238.3` (deuxieme etiquette);
- du **programme** qui utilise le port 58760 vers celui du port 443, en TCP,
  c'est-a-dire du web securise (troisieme etiquette);
- il ne transportait **aucune donnee**, c'etait juste un accuse de reception.

---

## 2. Le voyage d'un paquet dans le code

Suivons un seul paquet, du cable jusqu'a l'ecran. Il traverse cinq etapes, et
chaque etape correspond a un dossier.

```
   la carte reseau
        |
        v
   [1] src/capture/     "donne-moi les octets bruts"
        |
        v
   [2] src/dissect/     "lis les etiquettes"
        |
        v
   [3] src/filter/      "est-ce que je garde ce paquet ?"
        |
        v
   [4] src/dissect/summary   "ecris-le en une phrase"
        |
        v
   [5] src/cli/         affiche a l'ecran
        ou
       src/storage/     enregistre dans un fichier
```

### Etape 1: aller chercher les octets

Le systeme d'exploitation ne laisse pas n'importe qui lire le trafic reseau:
il faudrait pouvoir espionner tout le monde. Il faut donc des privileges,
d'ou le `sudo`.

Une fois l'autorisation obtenue, on demande au systeme "donne-moi tout ce qui
passe sur cette carte". Il repond avec une suite d'octets, rien de plus.

Ce n'est pas fait pareil selon le systeme, d'ou deux fichiers:
- `capture_linux.cpp` pour Linux;
- `capture_bsd.cpp` pour macOS et FreeBSD.

Un seul des deux est compile, celui qui correspond a la machine.

### Etape 2: lire les etiquettes

C'est le coeur du projet. On recoit un tas d'octets et il faut y reconnaitre
les etiquettes. Chaque protocole a sa place fixe: sur Ethernet, les 6 premiers
octets sont l'adresse du destinataire, les 6 suivants celle de l'expediteur,
et les 2 d'apres disent ce qu'il y a en dessous.

Un fichier par protocole:
- `ethernet.cpp`, `ipv4.cpp`, `tcp.cpp`, `udp.cpp`.

Et `decode.cpp` les enchaine: il epluche les couches l'une apres l'autre et
s'arrete des qu'une ne se laisse pas lire.

**La regle d'or de cette etape:** avant de lire un octet, on verifie qu'il
existe. Un paquet peut etre coupe, ou fabrique expres pour faire planter le
programme. C'est le role de `has_bytes` dans `net/bytes.cpp`.

### Etape 3: garder ou jeter

Si tu as donne une regle avec `-f`, par exemple `tcp and port 443`, le paquet
passe devant elle. La regle a ete transformee en petit arbre au demarrage:

```
        ET
       /  \
     tcp   port 443
```

Pour savoir si on garde le paquet, on parcourt l'arbre en posant chaque
question. Ici: "est-ce du TCP ?" et "un des deux ports vaut-il 443 ?".

Sans regle, tout passe.

### Etape 4: ecrire la phrase

`summary.cpp` prend le paquet decode et fabrique la ligne de texte. C'est lui
qui decide de l'ordre des informations et des annotations entre crochets.

### Etape 5: afficher ou enregistrer

Soit on affiche la ligne, soit on ecrit le paquet dans un fichier `.pcap`,
le format que comprennent Wireshark et tcpdump.

---

## 3. A quoi sert chaque dossier

| Dossier | En une phrase | Analogie |
|---|---|---|
| `src/net/` | Les outils de base: lire des nombres, manipuler des adresses, calculer une somme de controle | la boite a outils |
| `src/capture/` | Parler a la carte reseau et au systeme | l'antenne |
| `src/dissect/` | Comprendre les etiquettes | le traducteur |
| `src/filter/` | Decider quels paquets garder | le videur a l'entree |
| `src/storage/` | Lire et ecrire des fichiers `.pcap` | l'archiviste |
| `src/cli/` | Comprendre ce que tu tapes, et afficher | l'accueil |
| `tests/` | Verifier que tout ca dit vrai | le controle qualite |

Les dependances vont dans un seul sens: `cli` connait tout le monde, les
dossiers du milieu ne connaissent que `net`, et `net` ne connait personne.

C'est ce qui permet de **tester le decodage sans rien capturer**: on lui donne
des octets ecrits a la main, et on verifie ce qu'il en dit.

---

## 4. Pourquoi autant de tests

Le sujet dit qu'un plantage fait perdre la note maximale de la partie
concernee. Or un analyseur reseau lit par definition des donnees qu'il ne
controle pas: n'importe qui peut envoyer un paquet fabrique pour le faire
tomber.

Deux protections:

1. **On coupe les paquets de test a toutes les positions possibles**, une par
   une, et le programme doit toujours repondre sans planter. Un paquet de 54
   octets donne donc 55 tests a lui tout seul.

2. **On recompile tout avec des detecteurs de bugs memoire**, qui font echouer
   le programme au moindre acces hors limites. Si un test passe sous ces
   detecteurs, il n'y a pas de debordement cache.

Et pour prouver que le decodage dit **vrai** et pas seulement qu'il ne plante
pas, on compare la sortie a celle de `tcpdump`, un outil qui ne partage aucune
ligne de code avec le notre. S'il dit la meme chose que nous sur les memes
octets, c'est juste.

---

## 5. Les trois phrases a retenir pour l'oral

> J'ouvre une socket brute pour recevoir les octets bruts de la carte reseau,
> et je decode les en-têtes a la main, sans aucune bibliotheque reseau.

> Avant chaque lecture je verifie qu'il reste assez d'octets, parce qu'un
> paquet fabrique expres ferait sinon planter le programme, et le sujet le
> sanctionne.

> Je prouve que mon decodage est juste en enregistrant un fichier `.pcap` et
> en le faisant relire par tcpdump et Wireshark: ils lisent les memes heures,
> les memes adresses et les memes ports que moi.
