# Preparation a la soutenance

Chaque point tient en deux ou trois phrases. C'est fait pour etre lu a voix
haute, pas pour etre recite mot a mot.

---

## Les bases

### Qu'est-ce qu'un paquet reseau ?

Une suite d'octets qui commence par plusieurs en-tetes empiles, puis les
donnees. Chaque en-tete est ecrit par une couche differente et sert a une
question differente: quelle carte reseau, quelle machine, quel programme.

### Quelles sont ces couches ?

Ethernet dit de quelle carte a quelle carte, sur le reseau local. IPv4 dit de
quelle machine a quelle machine, a travers Internet. TCP ou UDP dit pour quel
programme sur cette machine, via un numero de port.

### Pourquoi trois couches et pas une ?

Parce que chacune peut changer sans toucher aux autres. Un paquet IP traverse
du Wi-Fi puis de la fibre: l'en-tete Ethernet est reecrit a chaque saut, l'IP
reste identique de bout en bout.

### Qu'est-ce qu'un port ?

Un numero sur 16 bits qui identifie le programme destinataire dans la machine.
Le 443 est attribue au web securise, le 53 au DNS. C'est une convention, rien
n'empeche d'y mettre autre chose, et c'est justement ce qu'un attaquant fait.

---

## La capture

### Comment tu recuperes les paquets ?

Je demande au noyau une socket brute, qui me donne les trames completes avec
leur en-tete Ethernet. Sous Linux c'est `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)`,
puis un `bind` sur une seule interface pour ne pas melanger les formats.

### Pourquoi ca demande sudo ?

Parce que lire le trafic brut permet de voir passer celui des autres. Le noyau
reserve donc cette capacite a l'administrateur. Le programme prend les
privileges uniquement pour ouvrir le descripteur, et n'en a plus besoin ensuite.

### C'est quoi le mode espion ?

Par defaut la carte jette les trames qui ne lui sont pas destinees. Le mode
promiscuous lui dit de tout remonter. Je l'active en adherant a un groupe de la
socket plutot qu'en modifiant l'interface, parce que le noyau annule cette
adhesion tout seul si le programme plante.

### Pourquoi deux fichiers de capture ?

Linux et la famille BSD n'offrent pas du tout la meme interface. Linux donne une
socket qui rend un paquet par appel, BSD donne un fichier special `/dev/bpf` qui
rend plusieurs paquets d'un coup dans un tampon. Un seul des deux fichiers est
compile, choisi par CMake.

### Et Windows, comment ca marche ?

Winsock2 seul ne donne jamais l'en-tete Ethernet sous Windows: contrairement a
Linux ou BSD, il n'y a aucune option native pour recevoir la trame brute.
L'encadrement pedagogique a confirme que Npcap est la solution attendue:
c'est la seule bibliotheque du projet, et elle sert uniquement a ouvrir la
capture et lire les trames (`capture_windows.cpp`). Le decodage Ethernet,
IPv4, TCP, UDP, le filtre et l'analyse restent notre code, identique aux
trois autres systemes. Lister les interfaces n'en a meme pas besoin: ca
passe par l'API Windows `GetAdaptersAddresses`, pas par Npcap.

---

## Le decodage

### Concretement, comment tu lis un en-tete ?

Chaque protocole a un format fixe decrit par sa RFC. Ethernet: 6 octets pour le
destinataire, 6 pour la source, 2 pour le type. Je lis donc a des positions
connues, et le champ type me dit quel decodeur appeler ensuite.

### Comment tu sais ou s'arrete un en-tete ?

Certains ont une taille fixe, comme Ethernet ou UDP. D'autres portent leur
propre taille: dans IPv4, les 4 bits de poids faible du premier octet donnent la
longueur de l'en-tete, comptee en mots de 4 octets.

### Pourquoi tu ne fais pas un cast vers une struct ?

Trois raisons. L'alignement n'est pas garanti, l'ordre des octets de la machine
ne correspond pas forcement a celui du reseau, et le compilateur peut inserer du
remplissage entre les champs. Je lis donc octet par octet et je recompose.

### C'est quoi l'ordre des octets ?

Sur le reseau, un nombre de deux octets s'ecrit toujours poids fort en premier.
Les processeurs Intel font l'inverse en memoire. On convertit d'habitude avec
`ntohs`, mais elle vient d'un en-tete reseau que le sujet interdit, donc je la
refais en deux lignes.

### C'est quoi une somme de controle ?

Un nombre calcule sur le contenu et range dans l'en-tete, pour detecter une
corruption en chemin. On additionne le tout par blocs de 16 bits, on replie les
retenues, on inverse les bits. Pour verifier, on recalcule sur l'en-tete complet
et on doit trouver zero.

---

## La securite, le coeur du sujet

### Quel est le risque principal d'un analyseur reseau ?

Il parse des donnees ecrites par quelqu'un d'autre, potentiellement hostile.
Chaque champ de longueur dans un paquet est un mensonge possible. Le sujet
sanctionne d'ailleurs tout plantage par la note maximale de la partie.

### Comment tu t'en proteges ?

Avant chaque lecture je verifie qu'il reste assez d'octets, avec une seule
fonction, `has_bytes`. Toute longueur annoncee par un paquet est ramenee a ce
que j'ai vraiment recu, et toute boucle sur une structure de taille variable a
une borne.

### Montre-moi le piege classique.

```c
if (offset + count <= size)   // FAUX
if (count <= size - offset)   // correct
```
La premiere version deborde si `offset` est enorme: la somme repasse a zero et
la condition devient vraie. Une lecture hors limites passe alors pour valide.
C'est une faille en trois caracteres.

### Comment tu prouves que ca ne plante pas ?

Je coupe chaque paquet de test a toutes les positions possibles, une par une, et
le programme doit repondre a chaque fois. Le tout recompile sous
AddressSanitizer, qui fait echouer au moindre acces hors limites.

### Et comment tu prouves que ton decodage dit VRAI ?

J'enregistre un fichier `.pcap` et je le fais relire par tcpdump, qui ne partage
aucune ligne de code avec le mien. Un script compare les heures, adresses et
ports extraits par les deux: sur ma capture de 50 paquets, aucune difference.

---

## Le filtre

### Comment marche ton langage de filtrage ?

En deux temps, comme tout analyseur. Je decoupe le texte en mots, puis je le lis
de gauche a droite en construisant un arbre, avec une fonction par niveau de
priorite: le OU appelle le ET, qui appelle le test elementaire.

### Pourquoi un arbre ?

Parce que `tcp and port 80` est naturellement un noeud ET avec deux enfants.
Pour savoir si on garde un paquet, on parcourt l'arbre en posant chaque
question. Ca rend les parentheses et les priorites gratuites.

### Pourquoi des index et pas des pointeurs ?

Les noeuds vivent dans un `std::vector` et se designent par leur position. Donc
aucune allocation a la main, rien a liberer, aucune fuite possible, et la copie
de l'objet fonctionne toute seule.

### Un plantage a ete trouve la-dedans, lequel ?

La recursion n'etait pas bornee: une regle avec 50000 parentheses epuisait la
pile. Pire, une longue chaine de `and` produisait un arbre tres profond qui ne
plantait qu'a l'evaluation, donc au premier paquet, loin de la cause. J'ai
ajoute deux limites, 64 niveaux d'imbrication et 256 conditions enchainees.

---

## Le stockage

### Pourquoi le format pcap ?

Parce que tcpdump et Wireshark le lisent, ce qui me permet de faire verifier mon
travail par des outils independants. Il est aussi minuscule: un en-tete de 24
octets, puis 16 octets devant chaque paquet.

### Pourquoi pas pcapng, son successeur ?

Il est bien plus riche mais bien plus gros a implementer, avec des blocs, des
options et plusieurs interfaces par fichier. Le format classique suffit a tout
ce que le sujet demande, et l'ajouter plus tard ne casserait rien puisque tout
est isole dans un seul fichier.

### Comment tu geres l'ordre des octets d'un fichier ecrit ailleurs ?

Le fichier commence par un nombre magique. Je le lis dans les deux sens et je
regarde lequel donne une valeur connue: ca me dit a la fois l'ordre des octets
du fichier et l'unite des dates.

---

## Deux surprises du monde reel

### Pourquoi les sommes de controle des paquets que tu envoies sont fausses ?

Parce que la carte reseau les calcule elle-meme, juste avant de mettre la trame
sur le cable, donc apres ma capture. Le champ est encore vide quand je le lis.
Je reconnais mes propres paquets a leur adresse MAC source et je le signale
autrement, au lieu de crier a l'erreur.

### Pourquoi tu vois des paquets de 34000 octets sur de l'Ethernet ?

Parce que la carte fusionne plusieurs trames recues en un seul gros paquet avant
de le remettre au systeme. On capture apres cette fusion. Ces deux mecanismes
s'appellent segmentation offload et receive offload, et on peut les desactiver
avec `ethtool -K` pour verifier.

---

## L'architecture

### Comment ton code est organise ?

Cinq dossiers, des dependances a sens unique. `net` contient les outils purs et
ne depend de personne. `dissect`, `capture` et `storage` ne dependent que de
`net`. `cli` connait tout le monde.

### Qu'est-ce que ca t'apporte ?

De pouvoir tester le decodage sans capturer quoi que ce soit: je lui donne des
octets ecrits a la main et je verifie ce qu'il en dit. C'est ce qui permet
d'avoir 482 verifications qui tournent sans privileges et sans reseau.

### Pourquoi une bibliotheque et un executable separes ?

Pour que les tests utilisent exactement le meme code que le programme, sans le
lancer. Et pour pouvoir ajouter une interface texte plus tard sans rien
dupliquer.

---

## Les questions pieges

### `linux/if_packet.h` et `net/bpf.h`, ce sont des bibliotheques reseau ?

Non, ce sont des definitions du noyau: zero fonction dedans, uniquement des
constantes et des dispositions memoire. Mon binaire n'est lie qu'a la
bibliotheque standard du C et du C++, et mon script de verification le prouve
a chaque execution.

### Et `getifaddrs`, `if_nametoindex` ?

Ce sont des fonctions systeme qui servent a designer une interface par son nom.
Elles ne lisent ni ne decodent aucun trafic, donc elles ne font rien de ce que
le sujet interdit. Mon script les affiche explicitement pour que ce soit assume
et pas cache.

### Pourquoi aucune bibliotheque externe, meme pour les tests ?

Parce que chaque dependance est une chose de plus a justifier, et que le besoin
etait petit. Mon framework de test tient en dix lignes, une macro qui compare et
compte les echecs. Le projet se compile donc avec juste un compilateur et CMake.

### Ton decodage marche sur FreeBSD et macOS ?

Le code est ecrit et il compile, mais je ne l'ai jamais execute dessus: je n'ai
ni Mac ni machine FreeBSD. C'est l'integration continue qui doit le prouver, et
c'est la principale limite que j'assume aujourd'hui.

### Comment tu evites que ton analyse crie tout le temps ?

Un detecteur qui alerte sans arret est un detecteur qu'on apprend a ignorer.
J'ai donc mesure sur dix minutes de navigation ordinaire: sept fausses alertes
au depart, zero apres correction.

Trois changements, tous venus de ce test: le detecteur de requetes compare un
debit et non un nombre total, les balises ne comptent qu'au-dela de dix secondes
d'intervalle et vers l'exterieur, et une option `--allow` permet de declarer
connus les reseaux legitimes. C'est elle qui permet de parler de connexion non
autorisee, puisque sans elle le programme ne sait pas ce qui est autorise.

### Qu'est-ce que tu ferais avec plus de temps ?

ARP et ICMP sont maintenant decodes; IPv6 reste identifie par son ethertype
mais pas lu. Avec plus de temps: IPv6, puis la reconnaissance de DNS et HTTP,
et enfin la detection d'un autre analyseur sur le reseau (deja etudiee en
notes personnelles, pas encore codee).
