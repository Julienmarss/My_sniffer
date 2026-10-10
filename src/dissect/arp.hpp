#pragma once

#include <stddef.h>
#include <stdint.h>

#include "net/ipv4_address.hpp"
#include "net/mac.hpp"

// Les deux operations qu'on rencontre en pratique: "qui a cette adresse IP ?"
// et sa reponse. D'autres existent (RFC 826 en prevoit d'autres, le
// "reverse ARP" en definit encore d'autres) mais ne circulent plus.
const uint16_t ARP_REQUEST = 1;
const uint16_t ARP_REPLY = 2;

// L'en-tete ARP (RFC 826), limite au cas Ethernet + IPv4: c'est la quasi
// totalite du trafic ARP reel, et les deux adresses ont alors une taille
// fixe. Un autre couple materiel/protocole est rejete par parse_arp, plutot
// que de generaliser une structure pour un cas qui n'arrive jamais.
//
//   +----------------+----------------+
//   | type materiel  | type protocole |
//   +-------+--------+----------------+
//   | TLmat | TLproto|   operation    |
//   +-------+--------+----------------+
//   |     adresse materielle emetteur  (6 octets)
//   +-----------------------------------
//   |      adresse IP emetteur         (4 octets)
//   +-----------------------------------
//   |     adresse materielle cible     (6 octets)
//   +-----------------------------------
//   |       adresse IP cible           (4 octets)
//   +-----------------------------------
//
struct ArpHeader {
    uint16_t operation;  // ARP_REQUEST ou ARP_REPLY
    Mac sender_mac;
    Ipv4 sender_ip;
    Mac target_mac;
    Ipv4 target_ip;
};

// Decode un en-tete ARP place a la position "offset" dans le paquet.
// Retourne false si le paquet est trop court, ou si ce n'est pas de l'ARP
// Ethernet/IPv4 (le seul cas gere ici).
bool parse_arp(const uint8_t *data, size_t size, size_t offset, ArpHeader *out);

// Donne un nom lisible pour une operation, "request" ou "reply".
const char *arp_operation_name(uint16_t operation);
