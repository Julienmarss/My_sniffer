#include "dissect/arp.hpp"

#include "net/bytes.hpp"

// Attribues par l'IANA. 1 veut dire "Ethernet", 0x0800 veut dire "IPv4": ce
// sont les seules valeurs que parse_arp accepte, voir arp.hpp.
static const uint16_t HARDWARE_TYPE_ETHERNET = 1;
static const uint16_t PROTOCOL_TYPE_IPV4 = 0x0800;

bool parse_arp(const uint8_t *data, size_t size, size_t offset, ArpHeader *out)
{
    // Les 8 premiers octets sont communs a tous les couples materiel/protocole:
    // on les lit d'abord pour savoir si le reste nous concerne.
    if (!has_bytes(size, offset, 8))
        return false;

    uint16_t hardware_type = read_u16(data, offset);
    uint16_t protocol_type = read_u16(data, offset + 2);
    uint8_t hardware_length = read_u8(data, offset + 4);
    uint8_t protocol_length = read_u8(data, offset + 5);

    if (hardware_type != HARDWARE_TYPE_ETHERNET || protocol_type != PROTOCOL_TYPE_IPV4)
        return false;

    // Les tailles d'adresse doivent correspondre a Ethernet (6) et IPv4 (4).
    // Un paquet qui annonce autre chose n'est pas coherent: on le refuse
    // plutot que de lire des adresses de la mauvaise taille.
    if (hardware_length != MAC_LENGTH || protocol_length != 4)
        return false;

    // En-tete complet pour ce couple: 8 + 6 + 4 + 6 + 4 = 28 octets.
    if (!has_bytes(size, offset, 28))
        return false;

    out->operation = read_u16(data, offset + 6);
    out->sender_mac = mac_from_bytes(data + offset + 8);
    out->sender_ip = ipv4_from_bytes(data + offset + 14);
    out->target_mac = mac_from_bytes(data + offset + 18);
    out->target_ip = ipv4_from_bytes(data + offset + 24);
    return true;
}

const char *arp_operation_name(uint16_t operation)
{
    switch (operation) {
    case ARP_REQUEST:
        return "request";
    case ARP_REPLY:
        return "reply";
    default:
        return "?";
    }
}
