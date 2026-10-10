# Compiler le projet

## Ce qu'il faut installer

Le projet n'a **aucune dependance externe**, a une exception pres: sous Windows,
Npcap est necessaire pour capturer (voir plus bas). Partout ailleurs, il faut
seulement:

| Outil | Version minimale | Pourquoi |
|---|---|---|
| Un compilateur C++ | GCC 7, Clang 6, ou Xcode 10 | le code est en C++17 |
| CMake | 3.16 | le systeme de compilation |

| Systeme | Commande d'installation |
|---|---|
| Debian, Ubuntu | `sudo apt install build-essential cmake` |
| Arch, Manjaro | `sudo pacman -S base-devel cmake` |
| Fedora | `sudo dnf install gcc-c++ cmake` |
| FreeBSD | `pkg install cmake` (le compilateur est deja la) |
| macOS | `xcode-select --install` puis `brew install cmake` |

## Compiler

```sh
cmake -S . -B build
cmake --build build
```

Le programme est dans `build/mysniffer`.

## Compiler sous Windows

Winsock2 seul ne donne jamais l'en-tete Ethernet sous Windows: le projet
utilise donc Npcap, uniquement pour ouvrir la capture (voir
[PRIVILEGES.md](PRIVILEGES.md)). Il faut:

1. Visual Studio 2022 (ou les Build Tools seuls) avec le composant "Desktop
   development with C++".
2. Le SDK Npcap (en-tetes et libs d'import, pas l'installeur): telechargez
   `npcap-sdk-*.zip` sur le site officiel de Npcap et decompressez-le.
3. Pour capturer reellement (pas seulement compiler), installez aussi Npcap
   lui-meme (l'installeur, pas seulement le SDK): voir
   [PRIVILEGES.md](PRIVILEGES.md).

```powershell
cmake -S . -B build -DNPCAP_SDK_DIR=C:\chemin\vers\npcap-sdk
cmake --build build --config Release
```

Le programme est dans `build\Release\mysniffer.exe`. Sans `NPCAP_SDK_DIR`,
la configuration s'arrete avec un message qui l'explique: c'est volontaire,
pour ne pas echouer plus tard avec une erreur d'edition de liens opaque.

## Lancer les tests

```sh
ctest --test-dir build
```

Ou directement, pour voir le detail:

```sh
./build/tests/tests
```

## Options de compilation

| Option | Effet |
|---|---|
| `-DWARNINGS_AS_ERRORS=ON` | Transforme tout warning en erreur. C'est ce que fait la CI. |
| `-DSANITIZE=ON` | Active les sanitizers, qui detectent les erreurs memoire a l'execution. |
| `-DBUILD_TESTS=OFF` | Ne compile pas les tests. |
| `-DCMAKE_BUILD_TYPE=Release` | Compile en optimise. |

Exemple, la commande que lance la CI:

```sh
cmake -S . -B build -DWARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build
```

Pour chercher un bug memoire:

```sh
cmake -S . -B build-asan -DSANITIZE=ON
cmake --build build-asan
./build-asan/tests/tests
```

## Installer

```sh
cmake --install build
```

Par defaut le programme va dans `/usr/local/bin`. Pour choisir ailleurs:

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$HOME/.local
cmake --build build
cmake --install build
```

## En cas de probleme

| Message | Cause et solution |
|---|---|
| `CMake 3.16 or higher is required` | CMake est trop ancien. Verifiez avec `cmake --version`. |
| `error: 'to_string' is not a member of 'std'` | Le compilateur n'est pas en C++17. Verifiez qu'il est assez recent. |
| `getifaddrs a echoue` | Erreur systeme rare. Le message qui suit donne la raison exacte. |
