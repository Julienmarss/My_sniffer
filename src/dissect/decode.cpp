#include "dissect/decode.hpp"

DecodedPacket decode_packet(const uint8_t *data, size_t size)
{
    DecodedPacket packet;

    packet.frame_length = size;
    packet.has_ethernet = false;
    packet.has_ipv4 = false;
    packet.has_arp = false;
    packet.has_tcp = false;
    packet.has_udp = false;
    packet.has_icmp = false;

    // On epluche les couches l'une apres l'autre, et on s'arrete des qu'une
    // ne se laisse pas lire. Chaque couche dit ou commence la suivante.
    if (!parse_ethernet(data, size, &packet.ethernet))
        return packet;
    packet.has_ethernet = true;

    if (packet.ethernet.type == ETHERTYPE_ARP) {
        packet.has_arp = parse_arp(data, size, packet.ethernet.payload_offset, &packet.arp);
        return packet;
    }

    if (packet.ethernet.type != ETHERTYPE_IPV4)
        return packet;

    if (!parse_ipv4(data, size, packet.ethernet.payload_offset, &packet.ipv4))
        return packet;
    packet.has_ipv4 = true;

    // Seul le premier morceau d'un paquet decoupe porte l'en-tete de transport.
    if (!ipv4_has_transport_header(packet.ipv4))
        return packet;

    if (packet.ipv4.protocol == IP_PROTOCOL_TCP) {
        packet.has_tcp = parse_tcp(data, size, packet.ipv4.payload_offset,
                                   packet.ipv4.payload_length, packet.ipv4.source,
                                   packet.ipv4.destination, &packet.tcp);
    } else if (packet.ipv4.protocol == IP_PROTOCOL_UDP) {
        packet.has_udp = parse_udp(data, size, packet.ipv4.payload_offset,
                                   packet.ipv4.source, packet.ipv4.destination,
                                   &packet.udp);
    } else if (packet.ipv4.protocol == IP_PROTOCOL_ICMP) {
        packet.has_icmp = parse_icmp(data, size, packet.ipv4.payload_offset,
                                     packet.ipv4.payload_length, &packet.icmp);
    }

    return packet;
}
