#pragma once

#include <stddef.h>
#include <stdint.h>

#include "net/ipv4_address.hpp"

// Numeros de protocole, attribues par l'IANA.
// Seuls TCP et UDP sont decodes; les autres sont juste nommes, pour que la
// sortie dise "IGMP" plutot qu'un chiffre nu.
const uint8_t IP_PROTOCOL_ICMP = 1;
const uint8_t IP_PROTOCOL_IGMP = 2;
const uint8_t IP_PROTOCOL_TCP = 6;
const uint8_t IP_PROTOCOL_UDP = 17;
const uint8_t IP_PROTOCOL_GRE = 47;
const uint8_t IP_PROTOCOL_ESP = 50;
const uint8_t IP_PROTOCOL_AH = 51;
const uint8_t IP_PROTOCOL_ICMPV6 = 58;
const uint8_t IP_PROTOCOL_OSPF = 89;
const uint8_t IP_PROTOCOL_SCTP = 132;

// L'en-tete IPv4, defini par la RFC 791.
//
//   0               1               2               3
//   +-------+-------+---------------+-------------------------------+
//   |version| taille|  type service |        longueur totale        |
//   +-------+-------+---------------+-----+-------------------------+
//   |        identification         |flags|    decalage fragment    |
//   +---------------+---------------+-----+-------------------------+
//   |      TTL      |   protocole   |      somme de controle        |
//   +---------------+---------------+-------------------------------+
//   |                     adresse source                            |
//   +---------------------------------------------------------------+
//   |                   adresse destination                         |
//   +---------------------------------------------------------------+
//
struct Ipv4Header {
    uint8_t version;           // vaut toujours 4 ici
    size_t header_length;      // en octets, deja converti
    uint16_t total_length;     // en-tete + donnees, annonce par le paquet
    uint16_t identification;   // sert a rassembler les fragments
    bool dont_fragment;        // interdit de decouper ce paquet
    bool more_fragments;       // d'autres morceaux suivent
    uint16_t fragment_offset;  // position de ce morceau, en octets
    uint8_t ttl;               // nombre de routeurs restants
    uint8_t protocol;          // IP_PROTOCOL_TCP, IP_PROTOCOL_UDP...
    bool checksum_valid;       // la somme de controle est-elle correcte
    Ipv4 source;
    Ipv4 destination;
    size_t payload_offset;     // ou commencent les donnees
    size_t payload_length;     // combien on en a reellement

    // Vrai quand la longueur annoncee par le paquet depasse ce qu'on a sous
    // la main. Deux causes possibles: la capture a coupe le paquet, ou bien
    // le paquet ment. Dans les deux cas on ne lit que ce qu'on a.
    bool length_exceeds_frame;
};

// Decode un en-tete IPv4 place a la position "offset" dans le paquet.
// Retourne false si le paquet est trop court ou si l'en-tete est incoherent.
bool parse_ipv4(const uint8_t *data, size_t size, size_t offset, Ipv4Header *out);

// Vrai si ce paquet est un morceau d'un paquet plus grand.
bool ipv4_is_fragment(const Ipv4Header &header);

// Vrai si ce morceau contient le debut du paquet, donc l'en-tete TCP ou UDP.
// Les morceaux suivants ne contiennent que des donnees brutes.
bool ipv4_has_transport_header(const Ipv4Header &header);

// Donne un nom lisible pour un numero de protocole, "TCP" par exemple.
// Pour un numero inconnu, rend le chiffre, dans un tampon partage: meme
// precaution que pour ethertype_name.
const char *ip_protocol_name(uint8_t protocol);
