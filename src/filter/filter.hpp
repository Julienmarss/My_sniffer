#pragma once

#include <stdint.h>

#include <string>
#include <vector>

#include "dissect/decode.hpp"
#include "net/ipv4_address.hpp"

// Le langage de filtrage.
//
// On ecrit une regle en toutes lettres, et le programme ne garde que les
// paquets qui y repondent. Quelques exemples:
//
//   tcp                                   les paquets TCP
//   port 443                              tout ce qui touche au port 443
//   dst port 53                           les requetes vers un serveur DNS
//   host 8.8.8.8                          tout ce qui parle a cette machine
//   net 192.168.0.0/16                    tout un reseau
//   tcp and dst port 80                   les deux conditions a la fois
//   tcp-flags syn and not tcp-flags ack   les debuts de connexion
//   not net 10.0.0.0/8                    tout sauf ce reseau
//   udp or icmp                           l'un ou l'autre
//   len > 1000                            les gros paquets
//
// La syntaxe ressemble a celle de tcpdump parce qu'elle est connue de tous.
// Mais l'analyse du texte et l'evaluation sont entierement ecrites ici: le
// sujet interdit la bibliotheque qui fait habituellement ce travail.
//
// Comme chez tcpdump, "host" et "net" regardent aussi les adresses ecrites a
// l'interieur des trames ARP (emetteur et cible), pas seulement les paquets IPv4.

// Ce que teste un noeud de la regle.
enum FilterKind {
    FILTER_AND,         // les deux enfants doivent repondre
    FILTER_OR,          // l'un des deux suffit
    FILTER_NOT,         // l'inverse de l'enfant de gauche
    FILTER_PROTOCOL,    // "tcp", "udp", "arp"...
    FILTER_HOST,        // "host 8.8.8.8"
    FILTER_NET,         // "net 192.168.0.0/16"
    FILTER_PORT,        // "port 80"
    FILTER_PORT_RANGE,  // "portrange 1000-2000"
    FILTER_TCP_FLAGS,   // "tcp-flags syn,ack"
    FILTER_LENGTH       // "len > 1000"
};

// De quel cote on regarde. Sans precision, les deux conviennent.
enum FilterDirection {
    DIRECTION_ANY,
    DIRECTION_SOURCE,
    DIRECTION_DESTINATION
};

// Les protocoles qu'on sait nommer dans une regle.
enum FilterProtocol {
    PROTOCOL_ETHERNET,
    PROTOCOL_ARP,
    PROTOCOL_VLAN,
    PROTOCOL_IPV4,
    PROTOCOL_IPV6,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_ICMP
};

// Les comparaisons acceptees par "len".
enum FilterComparison {
    COMPARE_LESS,
    COMPARE_LESS_OR_EQUAL,
    COMPARE_GREATER,
    COMPARE_GREATER_OR_EQUAL,
    COMPARE_EQUAL,
    COMPARE_NOT_EQUAL
};

// Un noeud de la regle.
//
// Une regle est un arbre: "tcp and port 80" devient un noeud ET avec deux
// enfants. Les enfants sont designes par leur position dans le tableau de la
// structure Filter, et non par un pointeur. C'est volontaire: pas d'allocation
// a la main, donc rien a liberer et rien qui puisse fuir.
struct FilterNode {
    FilterKind kind;
    int left;                    // position de l'enfant gauche, -1 si aucun
    int right;                   // position de l'enfant droit, -1 si aucun

    FilterDirection direction;   // pour host, net, port
    FilterProtocol protocol;     // pour FILTER_PROTOCOL
    Ipv4 address;                // pour host et net
    int prefix_length;           // pour net: le nombre apres le "/"
    uint16_t port_low;           // pour port et portrange
    uint16_t port_high;
    uint8_t flags_mask;          // pour tcp-flags
    FilterComparison comparison; // pour len
    uint32_t value;              // pour len
};

// Une regle complete, prete a etre appliquee.
struct Filter {
    std::vector<FilterNode> nodes;
    int root;   // position du sommet de l'arbre, -1 quand la regle est vide
};

// Une regle vide, qui laisse tout passer.
Filter filter_accept_all(void);

// Vrai si la regle laisse tout passer.
bool filter_is_empty(const Filter &filter);

// Analyse le texte d'une regle.
//
// En cas d'erreur de syntaxe, retourne false et ecrit dans "error" ce qui ne
// va pas, avec le mot fautif. Le filtre est alors inutilisable.
bool filter_parse(const std::string &text, Filter *filter, std::string *error);

// Vrai si ce paquet repond a la regle. Une regle vide accepte tout.
bool filter_matches(const Filter &filter, const DecodedPacket &packet);
