#include "dissect/ipv4.hpp"

#include <stdio.h>

#include "net/bytes.hpp"
#include "net/checksum.hpp"

bool parse_ipv4(const uint8_t *data, size_t size, size_t offset, Ipv4Header *out)
{
    // L'en-tete fait au minimum 20 octets.
    if (!has_bytes(size, offset, 20))
        return false;

    // Le premier octet porte deux champs de 4 bits: la version, puis la taille.
    uint8_t version_and_length = read_u8(data, offset);

    // Les 4 bits de poids fort donnent la version.
    out->version = version_and_length >> 4;
    if (out->version != 4)
        return false;

    // Les 4 bits de poids faible donnent la taille de l'en-tete, comptee en
    // mots de 4 octets. Le minimum legal est 5, soit 20 octets. Une valeur
    // plus petite est forcement un paquet casse ou malveillant.
    size_t words = version_and_length & 0x0f;

    if (words < 5)
        return false;
    out->header_length = words * 4;

    // L'en-tete peut etre plus grand que 20 octets s'il porte des options.
    // On verifie qu'on a bien recu tout ca avant de lire plus loin.
    if (!has_bytes(size, offset, out->header_length))
        return false;

    out->total_length = read_u16(data, offset + 2);
    out->identification = read_u16(data, offset + 4);

    uint16_t flags_and_offset = read_u16(data, offset + 6);

    out->dont_fragment = (flags_and_offset & 0x4000) != 0;
    out->more_fragments = (flags_and_offset & 0x2000) != 0;
    // Le decalage est compte en blocs de 8 octets, d'ou la multiplication.
    out->fragment_offset = static_cast<uint16_t>((flags_and_offset & 0x1fff) * 8);

    out->ttl = read_u8(data, offset + 8);
    out->protocol = read_u8(data, offset + 9);
    out->source = ipv4_from_bytes(data + offset + 12);
    out->destination = ipv4_from_bytes(data + offset + 16);

    // La somme de controle ne couvre que l'en-tete, pas les donnees.
    // En la recalculant sur l'en-tete complet, champ de somme inclus,
    // on doit trouver zero si rien n'a ete abime en chemin.
    out->checksum_valid = internet_checksum(data + offset, out->header_length) == 0;

    // La longueur annoncee doit au moins contenir l'en-tete.
    if (out->total_length < out->header_length)
        return false;

    out->payload_offset = offset + out->header_length;
    out->payload_length = out->total_length - out->header_length;

    // La longueur annoncee vient du paquet, donc on ne lui fait pas confiance.
    // Si elle depasse ce qu'on a vraiment recu, on garde ce qu'on a.
    // Ca arrive normalement quand la capture tronque les gros paquets.
    size_t available = size - out->payload_offset;

    out->length_exceeds_frame = out->payload_length > available;
    if (out->length_exceeds_frame)
        out->payload_length = available;

    return true;
}

bool ipv4_is_fragment(const Ipv4Header &header)
{
    return header.more_fragments || header.fragment_offset > 0;
}

bool ipv4_has_transport_header(const Ipv4Header &header)
{
    // Seul le premier morceau porte l'en-tete TCP ou UDP.
    // Un morceau de decalage non nul ne contient que la suite des donnees.
    return header.fragment_offset == 0;
}

const char *ip_protocol_name(uint8_t protocol)
{
    // Tampon partage, ecrase au prochain appel: voir l'en-tete.
    static char unknown[8];

    switch (protocol) {
    case IP_PROTOCOL_ICMP:
        return "ICMP";
    case IP_PROTOCOL_IGMP:
        return "IGMP";
    case IP_PROTOCOL_TCP:
        return "TCP";
    case IP_PROTOCOL_UDP:
        return "UDP";
    case IP_PROTOCOL_GRE:
        return "GRE";
    case IP_PROTOCOL_ESP:
        return "ESP";
    case IP_PROTOCOL_AH:
        return "AH";
    case IP_PROTOCOL_ICMPV6:
        return "ICMPv6";
    case IP_PROTOCOL_OSPF:
        return "OSPF";
    case IP_PROTOCOL_SCTP:
        return "SCTP";
    default:
        snprintf(unknown, sizeof(unknown), "%u", protocol);
        return unknown;
    }
}
