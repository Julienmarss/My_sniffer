#include "filter/filter.hpp"

#include "dissect/ethernet.hpp"
#include "dissect/ipv4.hpp"

Filter filter_accept_all(void)
{
    Filter filter;

    filter.root = -1;
    return filter;
}

bool filter_is_empty(const Filter &filter)
{
    return filter.root < 0;
}

// Les deux adresses IP du paquet, quand il en a.
//
// Une trame ARP porte aussi deux adresses IP, l'emetteur et la cible, meme
// sans en-tete IPv4: "host"/"net" les voient aussi, comme chez tcpdump.
static bool packet_addresses(const DecodedPacket &packet, Ipv4 *source, Ipv4 *destination)
{
    if (packet.has_ipv4) {
        *source = packet.ipv4.source;
        *destination = packet.ipv4.destination;
        return true;
    }
    if (packet.has_arp) {
        *source = packet.arp.sender_ip;
        *destination = packet.arp.target_ip;
        return true;
    }
    return false;
}

// Les deux ports du paquet, quand il en a. TCP et UDP en ont, les autres non.
static bool packet_ports(const DecodedPacket &packet, uint16_t *source, uint16_t *destination)
{
    if (packet.has_tcp) {
        *source = packet.tcp.source_port;
        *destination = packet.tcp.destination_port;
        return true;
    }
    if (packet.has_udp) {
        *source = packet.udp.source_port;
        *destination = packet.udp.destination_port;
        return true;
    }
    return false;
}

// Combine les deux resultats selon le cote demande par la regle.
// Sans precision, il suffit que l'un des deux reponde.
static bool keep_direction(FilterDirection direction, bool source, bool destination)
{
    if (direction == DIRECTION_SOURCE)
        return source;
    if (direction == DIRECTION_DESTINATION)
        return destination;
    return source || destination;
}

static bool matches_protocol(const DecodedPacket &packet, FilterProtocol protocol)
{
    switch (protocol) {
    case PROTOCOL_ETHERNET:
        return packet.has_ethernet;
    case PROTOCOL_ARP:
        return packet.has_ethernet && packet.ethernet.type == ETHERTYPE_ARP;
    case PROTOCOL_VLAN:
        // Une etiquette VLAN a ete sautee si les donnees ne commencent pas
        // a la position habituelle de 14 octets.
        return packet.has_ethernet && packet.ethernet.payload_offset > 14;
    case PROTOCOL_IPV6:
        return packet.has_ethernet && packet.ethernet.type == ETHERTYPE_IPV6;
    case PROTOCOL_IPV4:
        return packet.has_ipv4;
    case PROTOCOL_TCP:
        return packet.has_tcp;
    case PROTOCOL_UDP:
        return packet.has_udp;
    case PROTOCOL_ICMP:
        return packet.has_ipv4 && packet.ipv4.protocol == IP_PROTOCOL_ICMP;
    }
    return false;
}

static bool matches_tcp_flags(const DecodedPacket &packet, uint8_t wanted)
{
    if (!packet.has_tcp)
        return false;

    uint8_t present = 0;

    if (packet.tcp.fin)
        present |= 0x01;
    if (packet.tcp.syn)
        present |= 0x02;
    if (packet.tcp.rst)
        present |= 0x04;
    if (packet.tcp.psh)
        present |= 0x08;
    if (packet.tcp.ack)
        present |= 0x10;
    if (packet.tcp.urg)
        present |= 0x20;
    if (packet.tcp.ece)
        present |= 0x40;
    if (packet.tcp.cwr)
        present |= 0x80;

    // Tous les drapeaux demandes doivent etre presents. D'autres peuvent
    // l'etre aussi: "tcp-flags syn" accepte donc un SYN+ACK.
    return (present & wanted) == wanted;
}

static bool matches_length(const FilterNode &node, size_t length)
{
    uint32_t actual = static_cast<uint32_t>(length);

    switch (node.comparison) {
    case COMPARE_LESS:
        return actual < node.value;
    case COMPARE_LESS_OR_EQUAL:
        return actual <= node.value;
    case COMPARE_GREATER:
        return actual > node.value;
    case COMPARE_GREATER_OR_EQUAL:
        return actual >= node.value;
    case COMPARE_EQUAL:
        return actual == node.value;
    case COMPARE_NOT_EQUAL:
        return actual != node.value;
    }
    return false;
}

// Evalue un noeud, en descendant dans ses enfants si besoin.
static bool evaluate(const Filter &filter, int index, const DecodedPacket &packet)
{
    if (index < 0 || index >= static_cast<int>(filter.nodes.size()))
        return false;

    const FilterNode &node = filter.nodes[static_cast<size_t>(index)];

    switch (node.kind) {
    case FILTER_AND:
        return evaluate(filter, node.left, packet) && evaluate(filter, node.right, packet);
    case FILTER_OR:
        return evaluate(filter, node.left, packet) || evaluate(filter, node.right, packet);
    case FILTER_NOT:
        return !evaluate(filter, node.left, packet);

    case FILTER_PROTOCOL:
        return matches_protocol(packet, node.protocol);

    case FILTER_HOST: {
        Ipv4 source, destination;

        if (!packet_addresses(packet, &source, &destination))
            return false;
        return keep_direction(node.direction, source == node.address,
                              destination == node.address);
    }

    case FILTER_NET: {
        Ipv4 source, destination;

        if (!packet_addresses(packet, &source, &destination))
            return false;
        return keep_direction(node.direction,
                              ipv4_in_network(source, node.address, node.prefix_length),
                              ipv4_in_network(destination, node.address,
                                                 node.prefix_length));
    }

    case FILTER_PORT: {
        uint16_t source, destination;

        if (!packet_ports(packet, &source, &destination))
            return false;
        return keep_direction(node.direction, source == node.port_low,
                              destination == node.port_low);
    }

    case FILTER_PORT_RANGE: {
        uint16_t source, destination;

        if (!packet_ports(packet, &source, &destination))
            return false;
        return keep_direction(node.direction,
                              source >= node.port_low && source <= node.port_high,
                              destination >= node.port_low && destination <= node.port_high);
    }

    case FILTER_TCP_FLAGS:
        return matches_tcp_flags(packet, node.flags_mask);

    case FILTER_LENGTH:
        return matches_length(node, packet.frame_length);
    }

    return false;
}

bool filter_matches(const Filter &filter, const DecodedPacket &packet)
{
    if (filter_is_empty(filter))
        return true;
    return evaluate(filter, filter.root, packet);
}
