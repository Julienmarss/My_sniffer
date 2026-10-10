#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "net/ipv4_address.hpp"

// L'en-tete TCP, defini par la RFC 9293 (qui remplace la vieille RFC 793).
//
//   0                   1                   2                   3
//   +-------------------------------+-------------------------------+
//   |         port source           |      port destination         |
//   +---------------------------------------------------------------+
//   |                     numero de sequence                        |
//   +---------------------------------------------------------------+
//   |                    numero d'acquittement                      |
//   +-------+-----------+-----------+-------------------------------+
//   | taille| reserve   |  drapeaux |            fenetre            |
//   +-------+-----------+-----------+-------------------------------+
//   |     somme de controle         |      pointeur urgent          |
//   +-------------------------------+-------------------------------+
//
struct TcpHeader {
    uint16_t source_port;
    uint16_t destination_port;
    // Les deux numeros ci-dessous ne servent pas encore a l'affichage. Ils
    // sont decodes des maintenant parce que le moteur d'analyse en dependra:
    // c'est en comparant les numeros d'acquittement qu'on repere les paquets
    // reemis et les acquittements en double, deux signes de reseau qui souffre.
    uint32_t sequence;          // position des donnees dans le flux
    uint32_t acknowledgment;    // ce qu'on a bien recu d'en face
    size_t header_length;       // en octets, deja converti

    // Les drapeaux. Ce sont eux qui racontent l'etat de la connexion.
    bool fin;   // fin de connexion, poliment
    bool syn;   // demande d'ouverture
    bool rst;   // fermeture brutale, souvent un refus
    bool psh;   // a livrer tout de suite a l'application
    bool ack;   // le champ acquittement est valable
    bool urg;   // donnees urgentes, quasiment jamais utilise

    // Les trois suivants servent a signaler la congestion du reseau avant
    // qu'elle ne provoque des pertes. Ils sont definis par la RFC 3168.
    bool ece;   // "j'ai vu de la congestion"
    bool cwr;   // "j'ai reduit mon debit en consequence"

    // Le bit 7 etait autrefois nomme NS, dans un mecanisme abandonne depuis.
    // L'IANA l'a reattribue en 2026 sous le nom AE, pour une version plus
    // fine du signalement de congestion. On affiche donc AE et non NS.
    bool ae;

    uint16_t window;         // combien d'octets on accepte encore
    bool checksum_valid;
    size_t payload_offset;   // ou commencent les donnees
    size_t payload_length;
};

// Decode un en-tete TCP place a la position "offset".
//
// "segment_length" est la taille du segment complet annoncee par la couche IP
// (en-tete TCP plus donnees). Elle sert a verifier la somme de controle, qui
// couvre aussi les adresses IP: on les passe donc en parametre.
bool parse_tcp(const uint8_t *data, size_t size, size_t offset,
               size_t segment_length, Ipv4 source_ip, Ipv4 destination_ip,
               TcpHeader *out);

// Ecrit les drapeaux actifs sous forme lisible, par exemple "SYN, ACK".
// Retourne "aucun" si le paquet n'en porte aucun.
std::string tcp_flags_string(const TcpHeader &header);
