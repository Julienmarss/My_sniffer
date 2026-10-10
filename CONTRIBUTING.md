# Contribuer

## Style du code

Le mot d'ordre est: **du code qu'on peut lire et expliquer**.

- C++17, mais ecrit simplement. Pas de templates, pas de metaprogrammation.
- Des fonctions libres et des `struct` simples plutot que des hierarchies de classes.
- Une fonction fait une chose et tient a l'ecran.
- Les commentaires sont en francais et expliquent **pourquoi**, pas **quoi**.
  Le code dit deja ce qu'il fait.
- Indentation: 4 espaces. Accolade a la ligne pour les fonctions.
  Le fichier `.clang-format` contient la regle exacte.

## Nommage

| Element | Regle | Exemple |
|---|---|---|
| Fichiers | minuscules | `bytes.cpp` |
| Types | majuscule initiale | `Interface`, `Mac` |
| Fonctions | minuscules avec underscore | `read_u16`, `mac_to_string` |
| Variables | minuscules avec underscore | `prefix_length` |

Les fonctions liees a un type portent son nom en prefixe: `mac_to_string`,
`ipv4_is_private`. C'est ce qui remplace les methodes, et ca reste lisible.

## Avant de proposer une modification

```sh
cmake -S . -B build -DWARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build
```

Tout nouveau code vient avec ses tests, dans `tests/`.
Le projet doit compiler sans le moindre warning: le sujet l'exige.

## Messages de commit

Format [Conventional Commits](https://www.conventionalcommits.org/fr/v1.0.0/):

```
<type>(<zone>): <description>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`.
Zones: `net`, `capture`, `dissect`, `filter`, `analysis`, `cli`, `build`, `ci`, `docs`.

Exemple: `feat(capture): lire les paquets sur Linux avec AF_PACKET`

## Versions

[Versionnage semantique](https://semver.org/lang/fr/). Chaque version publiee
a son etiquette `vX.Y.Z` et sa section dans `CHANGELOG.md`.
