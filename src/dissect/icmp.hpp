#pragma once

#include <stddef.h>
#include <stdint.h>

// Types ICMP les plus courants (RFC 792). Il en existe d'autres, plus rares:
// icmp_type_name rend "?" pour ceux-la, plutot que de tous les lister.
const uint8_t ICMP_ECHO_REPLY = 0;
const uint8_t ICMP_DESTINATION_UNREACHABLE = 3;
const uint8_t ICMP_ECHO_REQUEST = 8;
const uint8_t ICMP_TIME_EXCEEDED = 11;

// L'en-tete ICMP (RFC 792). Les 4 premiers octets sont communs a tous les
// types; les 4 suivants changent de sens selon le type. On ne decode ce
// second groupe que pour l'echo (la requete et la reponse du "ping"), le cas
// de loin le plus frequent; les autres types sont nommes mais pas detailles.
//
//   0                   1                   2                   3
//   +-------+-------+-------------------------------+
//   | type  | code  |        somme de controle       |
//   +-------+-------+---------------+-----------------+
//   | identifiant (echo seulement)  | sequence (idem) |
//   +---------------------------------------------------+
//
struct IcmpHeader {
    uint8_t type;
    uint8_t code;
    bool checksum_valid;

    bool has_echo;  // vrai seulement pour les types 0 et 8
    uint16_t echo_identifier;
    uint16_t echo_sequence;

    size_t payload_offset;
    size_t payload_length;
};

// Decode un en-tete ICMP place a la position "offset".
//
// "message_length" est la taille du message ICMP annoncee par la couche IP
// (en-tete ICMP plus donnees): sert a verifier la somme de controle, qui ici
// ne couvre que le message lui-meme, sans pseudo en-tete.
bool parse_icmp(const uint8_t *data, size_t size, size_t offset,
                size_t message_length, IcmpHeader *out);

// Donne un nom lisible pour un type ICMP, "echo request" par exemple.
// Rend "?" pour un type que ce programme ne nomme pas.
const char *icmp_type_name(uint8_t type);
