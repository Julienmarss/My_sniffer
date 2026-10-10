#include "dissect/summary.hpp"

#include <stdio.h>
#include <time.h>

#include "dissect/arp.hpp"
#include "dissect/ethernet.hpp"
#include "dissect/icmp.hpp"
#include "dissect/ipv4.hpp"

// Largeur des colonnes, en caracteres.
//
// Elles servent a ce que chaque information tombe toujours au meme endroit,
// ligne apres ligne. Sur une capture reelle on lit des centaines de lignes:
// si les colonnes bougent, l'oeil ne peut plus descendre une colonne du regard.
//
// La largeur des adresses est celle du cas le plus long, "255.255.255.255:65535".
static const size_t ENDPOINT_WIDTH = 21;
static const size_t PROTOCOL_WIDTH = 4;   // "ICMP"
static const size_t FLAGS_WIDTH = 11;     // "SYN,ACK,PSH"

// Taille maximale des donnees d'une trame Ethernet ordinaire.
// Un paquet IP qui annonce plus que ca n'a pas pu voyager d'un seul tenant:
// c'est la carte reseau qui a fusionne plusieurs trames avant de nous les
// remettre. Les reseaux a trames geantes existent, mais restent rares.
static const uint16_t ETHERNET_MAX_PAYLOAD = 1500;

// Vrai quand le paquet est trop gros pour etre passe tel quel sur le cable.
static bool assembled_by_hardware(const Ipv4Header &ip)
{
    return ip.total_length > ETHERNET_MAX_PAYLOAD;
}

// localtime_r n'existe pas sous Windows: MSVC fournit localtime_s, avec les
// arguments dans l'autre ordre et un code d'erreur plutot qu'un pointeur.
static bool portable_localtime(const time_t *when, struct tm *broken)
{
#if defined(_WIN32)
    return localtime_s(broken, when) == 0;
#else
    return localtime_r(when, broken) != NULL;
#endif
}

// Ecrit l'heure sous la forme 00:43:12.123456.
static std::string format_time(long seconds, long microseconds)
{
    time_t raw = static_cast<time_t>(seconds);
    struct tm broken;
    char text[32];

    // Si la conversion echoue, on affiche des zeros plutot que n'importe quoi.
    if (!portable_localtime(&raw, &broken))
        return "00:00:00.000000";

    snprintf(text, sizeof(text), "%02d:%02d:%02d.%06ld",
             broken.tm_hour, broken.tm_min, broken.tm_sec, microseconds);
    return std::string(text);
}

// Aligne le nombre d'octets a droite, pour que les chiffres forment une
// colonne et qu'un gros paquet saute aux yeux au milieu des petits.
static std::string format_size(size_t bytes)
{
    char text[32];

    snprintf(text, sizeof(text), "%5zu octets", bytes);
    return std::string(text);
}

// Vrai si le paquet a ete emis par une des cartes de cette machine.
static bool sent_by_this_machine(const Mac &source, const SummaryOptions &options)
{
    for (size_t i = 0; i < options.local_macs.size(); i++) {
        if (source == options.local_macs[i])
            return true;
    }
    return false;
}

// Une extremite de la conversation: "192.168.1.10:443", ou juste l'adresse
// quand le protocole n'a pas de port.
static std::string endpoint(const Palette &palette, const std::string &address, int port)
{
    std::string text = address;

    if (port >= 0)
        text += ":" + std::to_string(port);
    return paint(palette, palette.address, pad_right(text, ENDPOINT_WIDTH));
}

// "source > destination", les deux extremites cote a cote.
// Un port negatif veut dire "pas de port".
static std::string flow(const Palette &palette, const Ipv4Header &ip,
                        int source_port, int destination_port)
{
    return endpoint(palette, ipv4_to_string(ip.source), source_port)
         + " > " + endpoint(palette, ipv4_to_string(ip.destination), destination_port);
}

// La colonne du protocole, puis celle des drapeaux. Les drapeaux n'existent
// que pour TCP; pour les autres on laisse la colonne vide afin que la taille
// reste alignee.
static std::string protocol_column(const Palette &palette, const std::string &name,
                                   const std::string &flags)
{
    return paint(palette, palette.protocol, pad_right(name, PROTOCOL_WIDTH))
         + "  " + paint(palette, palette.flags, pad_right(flags, FLAGS_WIDTH));
}

// Une annotation entre crochets.
// En gris quand elle EXPLIQUE quelque chose de normal, en rouge quand elle
// signale un vrai probleme. C'est toute la difference entre "la carte a
// calcule la somme apres coup" et "cette somme est fausse".
static std::string note(const Palette &palette, const char *color, const std::string &text)
{
    return "  " + paint(palette, color, "[" + text + "]");
}

// Decrit ce qu'il y a au-dessus d'IPv4: TCP, UDP, ou autre chose.
static std::string describe_transport(const DecodedPacket &packet, const Palette &palette,
                                      bool sent_by_us, bool *checksum_problem)
{
    const Ipv4Header &ip = packet.ipv4;

    // Un paquet coupe en morceaux ne porte son en-tete TCP ou UDP que dans
    // son premier morceau. Les suivants ne contiennent que des donnees.
    if (!ipv4_has_transport_header(ip)) {
        return flow(palette, ip, -1, -1)
             + "  " + protocol_column(palette, ip_protocol_name(ip.protocol), "")
             + "  " + format_size(ip.payload_length)
             + note(palette, palette.dim,
                    "fragment, decalage " + std::to_string(ip.fragment_offset));
    }

    if (ip.protocol == IP_PROTOCOL_TCP) {
        if (!packet.has_tcp) {
            return flow(palette, ip, -1, -1)
                 + "  " + protocol_column(palette, "TCP", "")
                 + note(palette, palette.alert, "en-tete TCP invalide");
        }

        const TcpHeader &tcp = packet.tcp;
        std::string line = flow(palette, ip, tcp.source_port, tcp.destination_port)
                         + "  " + protocol_column(palette, "TCP", tcp_flags_string(tcp))
                         + "  " + format_size(tcp.payload_length);

        // On ne peut juger la somme de controle que si on a le segment entier.
        // Si la capture l'a coupe, le calcul porte sur des donnees incompletes
        // et se trompe forcement: se taire vaut mieux qu'accuser a tort.
        if (!tcp.checksum_valid && !ip.length_exceeds_frame) {
            // Quand la carte a reassemble le paquet, l'annotation de taille
            // ajoutee plus loin dit deja pourquoi la somme ne tombe pas juste.
            if (sent_by_us)
                line += note(palette, palette.dim, "somme calculee par la carte");
            else if (!assembled_by_hardware(ip))
                line += note(palette, palette.alert, "somme TCP invalide");
            *checksum_problem = true;
        }
        return line;
    }

    if (ip.protocol == IP_PROTOCOL_UDP) {
        if (!packet.has_udp) {
            return flow(palette, ip, -1, -1)
                 + "  " + protocol_column(palette, "UDP", "")
                 + note(palette, palette.alert, "en-tete UDP invalide");
        }

        const UdpHeader &udp = packet.udp;
        std::string line = flow(palette, ip, udp.source_port, udp.destination_port)
                         + "  " + protocol_column(palette, "UDP", "")
                         + "  " + format_size(udp.payload_length);

        // Meme regle que pour TCP: on se tait si le paquet a ete coupe.
        if (udp.has_checksum && !udp.checksum_valid && !ip.length_exceeds_frame) {
            if (sent_by_us)
                line += note(palette, palette.dim, "somme calculee par la carte");
            else if (!assembled_by_hardware(ip))
                line += note(palette, palette.alert, "somme UDP invalide");
            *checksum_problem = true;
        }
        return line;
    }

    if (ip.protocol == IP_PROTOCOL_ICMP) {
        if (!packet.has_icmp) {
            return flow(palette, ip, -1, -1)
                 + "  " + protocol_column(palette, "ICMP", "")
                 + note(palette, palette.alert, "en-tete ICMP invalide");
        }

        const IcmpHeader &icmp = packet.icmp;
        std::string line = flow(palette, ip, -1, -1)
                         + "  " + protocol_column(palette, "ICMP", icmp_type_name(icmp.type))
                         + "  " + format_size(icmp.payload_length);

        if (icmp.has_echo) {
            line += note(palette, palette.dim,
                         "id=" + std::to_string(icmp.echo_identifier)
                         + " seq=" + std::to_string(icmp.echo_sequence));
        }

        // Meme reserve que pour TCP et UDP: on se tait si le paquet a ete coupe.
        if (!icmp.checksum_valid && !ip.length_exceeds_frame) {
            if (sent_by_us)
                line += note(palette, palette.dim, "somme calculee par la carte");
            else if (!assembled_by_hardware(ip))
                line += note(palette, palette.alert, "somme ICMP invalide");
            *checksum_problem = true;
        }
        return line;
    }

    return flow(palette, ip, -1, -1)
         + "  " + protocol_column(palette, ip_protocol_name(ip.protocol), "")
         + "  " + format_size(ip.payload_length);
}

PacketSummary summarize_packet(const DecodedPacket &packet, long seconds, long microseconds,
                               const SummaryOptions &options)
{
    const Palette &palette = options.palette;
    PacketSummary result;

    result.checksum_problem = false;
    result.line = paint(palette, palette.dim, format_time(seconds, microseconds));

    if (!packet.has_ethernet) {
        result.line += "  " + paint(palette, palette.alert,
                                    "trame trop courte ("
                                    + std::to_string(packet.frame_length) + " octets)");
        return result;
    }

    result.line += "  " + paint(palette, palette.dim,
                                mac_to_string(packet.ethernet.source) + " > "
                                + mac_to_string(packet.ethernet.destination));

    bool sent_by_us = sent_by_this_machine(packet.ethernet.source, options);

    if (packet.ethernet.type == ETHERTYPE_ARP) {
        if (!packet.has_arp) {
            result.line += "  " + paint(palette, palette.alert, "ARP (en-tete invalide)");
            return result;
        }

        const ArpHeader &arp = packet.arp;

        result.line += "  " + endpoint(palette, ipv4_to_string(arp.sender_ip), -1)
                     + " > " + endpoint(palette, ipv4_to_string(arp.target_ip), -1)
                     + "  " + protocol_column(palette, "ARP", arp_operation_name(arp.operation));
        return result;
    }

    // Pour tout ce qui n'est pas IPv4 ou ARP, on s'arrete au type. IPv6 et le
    // reste restent en bonus. La colonne des adresses reste vide mais
    // occupe sa place, pour que le nom du protocole tombe ou on l'attend.
    if (packet.ethernet.type != ETHERTYPE_IPV4) {
        result.line += "  " + pad_right("", ENDPOINT_WIDTH) + "   "
                     + pad_right("", ENDPOINT_WIDTH) + "  "
                     + paint(palette, palette.protocol,
                             ethertype_name(packet.ethernet.type));
        return result;
    }

    if (!packet.has_ipv4) {
        result.line += "  " + paint(palette, palette.alert, "IPv4 (en-tete invalide)");
        return result;
    }

    result.line += "  " + describe_transport(packet, palette, sent_by_us,
                                             &result.checksum_problem);

    // Un paquet trop gros pour une trame Ethernet n'a pas voyage tel quel:
    // c'est la carte qui a fusionne plusieurs trames avant de nous le donner.
    // Sa somme de controle n'a alors plus de sens, d'ou la mention.
    if (assembled_by_hardware(packet.ipv4)) {
        result.line += note(palette, palette.dim,
                            "assemble par la carte a partir de plusieurs trames,"
                            " somme perdue");
    }

    if (packet.ipv4.length_exceeds_frame)
        result.line += note(palette, palette.alert, "longueur IP annoncee superieure a la trame");

    if (!packet.ipv4.checksum_valid) {
        if (sent_by_us)
            result.line += note(palette, palette.dim, "somme IP calculee par la carte");
        else
            result.line += note(palette, palette.alert, "somme IP invalide");
        result.checksum_problem = true;
    }
    return result;
}
