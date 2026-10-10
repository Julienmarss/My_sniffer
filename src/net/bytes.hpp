#pragma once

#include <stddef.h>
#include <stdint.h>

// Lecture des nombres a l'interieur d'un paquet reseau.
//
// Sur le reseau, les nombres de plusieurs octets sont ecrits en "big-endian":
// l'octet de poids fort en premier (RFC 791, annexe B). On les relit ici
// octet par octet et on les recompose a la main. Deux avantages:
//   1. le resultat est le meme quelle que soit la machine (Intel, ARM...);
//   2. on n'a pas besoin de ntohs/ntohl, qui viennent de <arpa/inet.h>,
//      un en-tete reseau que le sujet nous interdit.
//
// ATTENTION: read_u8/16/32 ne verifient PAS la taille du paquet.
// L'appelant doit d'abord appeler has_bytes(). C'est volontaire: on verifie
// une seule fois la taille d'un en-tete complet, puis on lit ses champs.

// Vrai s'il reste au moins "count" octets a partir de "offset"
// dans un tampon de taille "size".
bool has_bytes(size_t size, size_t offset, size_t count);

// Lit 1 octet a la position offset.
uint8_t read_u8(const uint8_t *data, size_t offset);

// Lit 2 octets en big-endian a la position offset.
uint16_t read_u16(const uint8_t *data, size_t offset);

// Lit 4 octets en big-endian a la position offset.
uint32_t read_u32(const uint8_t *data, size_t offset);
