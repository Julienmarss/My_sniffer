#include "dissect/ethernet.hpp"

#include <stdio.h>

#include "net/bytes.hpp"

bool parse_ethernet(const uint8_t *data, size_t size, EthernetHeader *out)
{
    // Un en-tete Ethernet fait 14 octets: 6 pour la destination,
    // 6 pour la source, 2 pour le type.
    if (!has_bytes(size, 0, 14))
        return false;

    out->destination = mac_from_bytes(data);
    out->source = mac_from_bytes(data + 6);
    out->type = read_u16(data, 12);
    out->payload_offset = 14;

    // Une trame peut porter une etiquette VLAN. Le champ type vaut alors
    // 0x8100 (ou 0x88a8 pour l'etiquette exterieure quand il y en a
    // plusieurs), et il est suivi de 4 octets d'etiquette, puis du vrai type.
    // Deux etiquettes au maximum: c'est ce que permet la norme QinQ, une
    // exterieure et une interieure. Au-dela, la trame est forcement fabriquee,
    // et une boucle sans borne serait une invitation a nous faire tourner
    // indefiniment sur un paquet malveillant.
    const int MAX_VLAN_TAGS = 2;
    int tags = 0;

    while ((out->type == ETHERTYPE_VLAN || out->type == ETHERTYPE_VLAN_OUTER)
           && tags < MAX_VLAN_TAGS) {
        if (!has_bytes(size, out->payload_offset, 4))
            return false;
        out->type = read_u16(data, out->payload_offset + 2);
        out->payload_offset += 4;
        tags++;
    }

    return true;
}

const char *ethertype_name(uint16_t type)
{
    // ATTENTION: pour un type inconnu, on rend un pointeur vers un tampon
    // partage. Le texte est donc ecrase au prochain appel. C'est sans danger
    // ici parce que l'appelant s'en sert immediatement, mais il ne faut pas
    // garder ce pointeur ni appeler la fonction deux fois dans la meme
    // expression.
    static char unknown[8];

    switch (type) {
    case ETHERTYPE_IPV4:
        return "IPv4";
    case ETHERTYPE_ARP:
        return "ARP";
    case ETHERTYPE_IPV6:
        return "IPv6";
    case ETHERTYPE_VLAN:
    case ETHERTYPE_VLAN_OUTER:
        return "VLAN";
    default:
        snprintf(unknown, sizeof(unknown), "0x%04x", type);
        return unknown;
    }
}
