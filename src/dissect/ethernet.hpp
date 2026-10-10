#pragma once

#include <stddef.h>
#include <stdint.h>

#include "net/mac.hpp"

// Ce que transporte la trame. La liste complete est tenue par l'IEEE,
// voici les valeurs qui nous concernent.
const uint16_t ETHERTYPE_IPV4 = 0x0800;
const uint16_t ETHERTYPE_ARP = 0x0806;
const uint16_t ETHERTYPE_IPV6 = 0x86dd;
const uint16_t ETHERTYPE_VLAN = 0x8100;
// Quand plusieurs etiquettes VLAN sont empilees (on parle de QinQ), celle de
// l'exterieur porte ce numero-la et non 0x8100. Les deux se sautent pareil.
const uint16_t ETHERTYPE_VLAN_OUTER = 0x88a8;

// L'en-tete d'une trame Ethernet.
//
//   +--------------+--------------+------+-----------------+
//   | destination  | source       | type | donnees         |
//   | 6 octets     | 6 octets     | 2 o. | ...             |
//   +--------------+--------------+------+-----------------+
//
struct EthernetHeader {
    Mac destination;
    Mac source;
    uint16_t type;          // ETHERTYPE_IPV4, ETHERTYPE_ARP...
    size_t payload_offset;  // ou commence ce qui suit l'en-tete
};

// Decode l'en-tete Ethernet au debut du paquet.
// Retourne false si la trame est trop courte pour en contenir un.
bool parse_ethernet(const uint8_t *data, size_t size, EthernetHeader *out);

// Donne un nom lisible pour un type Ethernet, "IPv4" par exemple.
// Retourne "0x????" si le type est inconnu.
//
// Le texte rendu pour un type inconnu vit dans un tampon partage: servez-vous
// en tout de suite, ne le gardez pas, et n'appelez pas cette fonction deux
// fois dans la meme expression.
const char *ethertype_name(uint16_t type);
