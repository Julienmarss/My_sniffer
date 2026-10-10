#pragma once

#include <stddef.h>
#include <stdint.h>

#include "net/ipv4_address.hpp"

// L'en-tete UDP, defini par la RFC 768. Il tient en 8 octets, c'est le plus
// simple de tous: UDP ne garantit rien, il se contente d'envoyer.
//
//   0                   1                   2                   3
//   +-------------------------------+-------------------------------+
//   |         port source           |      port destination         |
//   +-------------------------------+-------------------------------+
//   |          longueur             |     somme de controle         |
//   +-------------------------------+-------------------------------+
//
struct UdpHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;         // en-tete plus donnees, annonce par le paquet
    bool has_checksum;       // en IPv4 la somme est facultative
    bool checksum_valid;
    size_t payload_offset;
    size_t payload_length;
};

// Decode un en-tete UDP place a la position "offset".
// Les adresses IP servent a verifier la somme de controle.
bool parse_udp(const uint8_t *data, size_t size, size_t offset,
               Ipv4 source_ip, Ipv4 destination_ip, UdpHeader *out);
