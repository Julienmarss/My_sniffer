# Installation

## Depuis les sources

C'est la seule methode pour l'instant, et elle ne demande que deux outils, un
compilateur C++ et CMake. Le detail par systeme est dans [BUILD.md](BUILD.md).

```sh
git clone https://github.com/Julienmarss/My_sniffer.git
cd My_sniffer
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

Le programme est alors installe dans `/usr/local/bin/mysniffer`.

Verifiez:

```sh
mysniffer --version
```

## Installer ailleurs que dans le systeme

Pour installer dans votre dossier personnel, sans administrateur:

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$HOME/.local
cmake --build build
cmake --install build
```

Assurez-vous que `$HOME/.local/bin` est dans votre `PATH`.

## Ce que l'installation copie

Un seul fichier: le programme lui-meme. Il n'y a ni bibliotheque partagee, ni
fichier de configuration, ni donnee annexe. Le programme n'a aucune dependance
en dehors de la bibliotheque standard du systeme.

## Autoriser la capture

L'installation ne donne aucun privilege particulier. Lire le trafic reseau en
demande. Deux possibilites:

```sh
sudo mysniffer capture
```

ou bien, sous Linux, accorder une fois pour toutes le droit minimal:

```sh
sudo setcap cap_net_raw+ep /usr/local/bin/mysniffer
```

Les autres systemes et le detail sont dans [PRIVILEGES.md](PRIVILEGES.md).

## Desinstaller

CMake ne fournit pas de cible de desinstallation. Comme un seul fichier est
copie, il suffit de le supprimer:

```sh
sudo rm /usr/local/bin/mysniffer
```

## Verifier que tout fonctionne

```sh
mysniffer --version
mysniffer interfaces
sudo mysniffer capture -c 5
```

La derniere commande doit afficher cinq paquets puis s'arreter.
