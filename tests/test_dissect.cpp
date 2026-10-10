#include "check.hpp"

#include "dissect/arp.hpp"
#include "dissect/ethernet.hpp"
#include "dissect/icmp.hpp"
#include "dissect/ipv4.hpp"
#include "dissect/tcp.hpp"
#include "dissect/udp.hpp"
#include "dissect/decode.hpp"
#include "dissect/summary.hpp"
#include "net/checksum.hpp"

#include <vector>

// Les trames ci-dessous sont de vrais paquets, avec de vraies sommes de
// controle. Les tester sur des donnees inventees ne prouverait rien.

// Trame reelle: Ethernet + IPv4 + TCP avec le drapeau SYN.
// 192.168.1.10:54321 vers 93.184.216.34:80, sommes de controle valides.
const uint8_t packet_tcp_syn[] = {
    0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
    0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
    0x26, 0xfd, 0xc0, 0xa8, 0x01, 0x0a, 0x5d, 0xb8, 0xd8, 0x22, 0xd4, 0x31,
    0x00, 0x50, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
    0xfa, 0xf0, 0x80, 0x36, 0x00, 0x00
};

// Trame reelle: Ethernet + IPv4 + UDP portant une requete DNS.
// 192.168.1.10:51000 vers 8.8.8.8:53, sommes de controle valides.
const uint8_t packet_udp_dns[] = {
    0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
    0x08, 0x00, 0x45, 0x00, 0x00, 0x3d, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x11,
    0x4c, 0xa8, 0xc0, 0xa8, 0x01, 0x0a, 0x08, 0x08, 0x08, 0x08, 0xc7, 0x38,
    0x00, 0x35, 0x00, 0x29, 0x70, 0x42, 0xab, 0xcd, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x07, 0x65,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0x01, 0x00, 0x01
};

// La meme trame TCP, mais avec une etiquette VLAN numero 100 inseree.
static const uint8_t packet_vlan[] = {
    0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
    0x81, 0x00, 0x00, 0x64, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x1c, 0x46,
    0x40, 0x00, 0x40, 0x06, 0x26, 0xfd, 0xc0, 0xa8, 0x01, 0x0a, 0x5d, 0xb8,
    0xd8, 0x22, 0xd4, 0x31, 0x00, 0x50, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x02, 0xfa, 0xf0, 0x80, 0x36, 0x00, 0x00
};

// Trame avec DEUX etiquettes VLAN empilees (QinQ): l'exterieure porte le
// numero 0x88a8, l'interieure 0x8100. Le vrai contenu est derriere.
static const uint8_t packet_qinq[] = {
    0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
    0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x26, 0xfd, 0xc0, 0xa8,
    0x01, 0x0a, 0x5d, 0xb8, 0xd8, 0x22, 0xd4, 0x31, 0x00, 0x50, 0x11, 0x11,
    0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x51, 0xff, 0x02, 0x00, 0x79, 0x70,
    0x00, 0x00
};

// Trame TCP portant les huit drapeaux a la fois, plus le bit AE.
// Cas de test repris du projet tcpdump.
static const uint8_t packet_all_flags[] = {
    0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
    0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
    0x26, 0xfd, 0xc0, 0xa8, 0x01, 0x0a, 0x5d, 0xb8, 0xd8, 0x22, 0xd4, 0x31,
    0x00, 0x50, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x51, 0xff,
    0x02, 0x00, 0x79, 0x70, 0x00, 0x00
};

// Trame dont l'en-tete IPv4 annonce 100 octets de plus qu'elle n'en contient.
// Un decodeur naif lirait au-dela de la memoire du paquet.
static const uint8_t packet_lying_length[] = {
    0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
    0x08, 0x00, 0x45, 0x00, 0x00, 0x8c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
    0x26, 0x99, 0xc0, 0xa8, 0x01, 0x0a, 0x5d, 0xb8, 0xd8, 0x22, 0x04, 0xd2,
    0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Trame ARP reelle: une requete "qui a 192.168.1.1 ?", envoyee en diffusion
// par c8:5e:a9:53:40:3a (192.168.1.10). L'adresse materielle cible est
// inconnue, donc a zero: c'est justement ce qu'on demande.
static const uint8_t packet_arp_request[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a,
    0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xc8, 0x5e,
    0xa9, 0x53, 0x40, 0x3a, 0xc0, 0xa8, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01
};

// Trame reelle: Ethernet + IPv4 + ICMP, une requete d'echo ("ping") avec
// identifiant 0x1234, numero de sequence 1, et 4 octets de donnees "abcd".
// 192.168.1.10 vers 8.8.8.8, sommes de controle valides.
static const uint8_t packet_icmp_echo[] = {
    0x5d, 0xb8, 0xd8, 0x22, 0xee, 0xff, 0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x30,
    0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x01,
    0x4c, 0xd5, 0xc0, 0xa8, 0x01, 0x0a, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00,
    0x21, 0x04, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64
};

// Verifie les trois corrections trouvees en comparant notre sortie a tcpdump
// sur de vrais fichiers du projet tcpdump.
static void test_edge_cases(void)
{
    EthernetHeader eth;

    // Deux etiquettes VLAN empilees doivent etre sautees toutes les deux.
    CHECK(parse_ethernet(packet_qinq, sizeof(packet_qinq), &eth) == true);
    CHECK(eth.type == ETHERTYPE_IPV4);
    CHECK(eth.payload_offset == 22);  // 14 + 4 + 4

    // Les huit drapeaux TCP, plus AE. Il manquait ECE, CWR et AE.
    Ipv4Header ip;
    TcpHeader tcp;

    CHECK(parse_ethernet(packet_all_flags, sizeof(packet_all_flags), &eth) == true);
    CHECK(parse_ipv4(packet_all_flags, sizeof(packet_all_flags),
                     eth.payload_offset, &ip) == true);
    CHECK(parse_tcp(packet_all_flags, sizeof(packet_all_flags), ip.payload_offset,
                    ip.payload_length, ip.source, ip.destination, &tcp) == true);
    CHECK(tcp.fin && tcp.syn && tcp.rst && tcp.psh);
    CHECK(tcp.ack && tcp.urg && tcp.ece && tcp.cwr);
    CHECK(tcp.ae == true);
    CHECK(tcp_flags_string(tcp) == "AE, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN");

    // Un en-tete IPv4 qui annonce plus grand que la trame doit etre signale,
    // et surtout ne jamais faire lire au-dela des octets recus.
    Ipv4Header lying;

    CHECK(parse_ipv4(packet_lying_length, sizeof(packet_lying_length), 14, &lying) == true);
    CHECK(lying.length_exceeds_frame == true);
    CHECK(lying.payload_offset + lying.payload_length <= sizeof(packet_lying_length));

    std::string line = summarize_packet(decode_packet(packet_lying_length,
                                                      sizeof(packet_lying_length)),
                                        0, 0, SummaryOptions()).line;

    CHECK(line.find("longueur IP annoncee") != std::string::npos);

    // Et comme toujours: coupees n'importe ou, ces trames ne doivent pas planter.
    for (size_t cut = 0; cut <= sizeof(packet_qinq); cut++)
        summarize_packet(decode_packet(packet_qinq, cut), 0, 0,
                                        SummaryOptions());
    for (size_t cut = 0; cut <= sizeof(packet_lying_length); cut++)
        summarize_packet(decode_packet(packet_lying_length, cut), 0, 0,
                                        SummaryOptions());
}

// Une carte reseau moderne fusionne plusieurs trames recues en un seul gros
// paquet avant de le remettre au systeme. On voit alors passer des paquets bien
// plus grands qu'une trame Ethernet, dont la somme de controle n'a plus de sens.
// Le programme doit le dire, et surtout ne pas crier a l'erreur.
static void test_hardware_assembly(void)
{
    // On fabrique une vraie trame de 2054 octets: 14 d'Ethernet, 20 d'IPv4,
    // 20 de TCP, et 2000 de donnees. C'est trop gros pour un cable Ethernet.
    const size_t payload = 2000;
    std::vector<uint8_t> frame(14 + 20 + 20 + payload, 0);

    // Ethernet: destination, source, type IPv4.
    for (int i = 0; i < 6; i++) {
        frame[i] = 0xaa;
        frame[6 + i] = 0xbb;
    }
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IPv4: version 4, en-tete de 20 octets, longueur totale annoncee.
    uint16_t total = static_cast<uint16_t>(20 + 20 + payload);

    frame[14] = 0x45;
    frame[16] = static_cast<uint8_t>(total >> 8);
    frame[17] = static_cast<uint8_t>(total & 0xff);
    frame[22] = 64;                 // TTL
    frame[23] = IP_PROTOCOL_TCP;
    frame[26] = 192; frame[27] = 168; frame[28] = 1; frame[29] = 10;
    frame[30] = 8; frame[31] = 8; frame[32] = 8; frame[33] = 8;

    uint16_t sum = internet_checksum(&frame[14], 20);

    frame[24] = static_cast<uint8_t>(sum >> 8);
    frame[25] = static_cast<uint8_t>(sum & 0xff);

    // TCP: ports et taille d'en-tete.
    frame[34] = 0x01; frame[35] = 0xbb;   // port source 443
    frame[36] = 0x30; frame[37] = 0x39;   // port destination 12345
    frame[46] = 0x50;                     // en-tete de 20 octets
    frame[47] = 0x10;                     // drapeau ACK

    Ipv4Header ip;

    CHECK(parse_ipv4(frame.data(), frame.size(), 14, &ip) == true);
    CHECK(ip.total_length == total);
    CHECK(ip.checksum_valid == true);
    // La trame contient bien tout ce qu'elle annonce: ce n'est pas une
    // longueur mensongere, juste un paquet assemble par la carte.
    CHECK(ip.length_exceeds_frame == false);

    PacketSummary summary = summarize_packet(decode_packet(frame.data(), frame.size()), 0, 0,
                                             SummaryOptions());

    CHECK(summary.line.find("assemble par la carte") != std::string::npos);
    // On ne doit pas accuser le paquet d'avoir une somme fausse: on sait
    // pourquoi elle ne tombe pas juste.
    CHECK(summary.line.find("somme TCP invalide") == std::string::npos);
}

// Quand la capture a coupe un paquet en cours de route, on n'a pas de quoi
// verifier sa somme de controle. Le programme doit alors se taire, et surtout
// pas afficher "somme invalide": ce serait accuser un paquet parfaitement sain.
//
// Ce test vient d'un audit qui avait trouve le contraire: le garde-fou etait
// ecrit sur une valeur deja ramenee a la taille disponible, donc toujours vrai.
static void test_truncated_no_false_alarm(void)
{
    // On reprend la trame TCP valide et on la coupe en plein milieu des
    // donnees, comme le ferait une capture limitee en taille.
    const size_t cut = 40;   // 14 Ethernet + 20 IPv4 + 6 octets de TCP seulement

    Ipv4Header ip;

    CHECK(parse_ipv4(packet_tcp_syn, cut, 14, &ip) == true);
    // La longueur annoncee depasse ce qui reste: c'est bien un paquet coupe.
    CHECK(ip.length_exceeds_frame == true);

    PacketSummary summary = summarize_packet(decode_packet(packet_tcp_syn, cut), 0, 0,
                                        SummaryOptions());

    CHECK(summary.line.find("longueur IP annoncee") != std::string::npos);
    CHECK(summary.line.find("somme TCP invalide") == std::string::npos);
    CHECK(summary.line.find("somme UDP invalide") == std::string::npos);
}

// Quand la carte reseau calcule elle-meme les sommes de controle, les paquets
// que la machine emet sont captures avant que le champ soit rempli. Le
// programme doit reconnaitre ces paquets a leur adresse source et le dire,
// au lieu de les accuser d'etre abimes.
//
// C'est le point technique le plus fin du programme, et il n'etait couvert par
// aucun test avant cet ajout.
static void test_own_packets_checksum(void)
{
    // On abime la somme de controle TCP de la trame de reference.
    uint8_t frame[sizeof(packet_tcp_syn)];

    memcpy(frame, packet_tcp_syn, sizeof(packet_tcp_syn));
    frame[50] ^= 0xff;   // un octet de la somme TCP

    // Cas 1: on ne connait aucune de nos adresses, comme pour un fichier venu
    // d'ailleurs. On constate simplement que la somme ne tombe pas juste.
    PacketSummary unknown = summarize_packet(decode_packet(frame, sizeof(frame)), 0, 0,
                                        SummaryOptions());

    CHECK(unknown.line.find("somme TCP invalide") != std::string::npos);
    CHECK(unknown.checksum_problem == true);

    // Cas 2: l'adresse source de cette trame est une des notres. On sait alors
    // pourquoi la somme est vide, et on ne crie pas a l'erreur.
    SummaryOptions ours = SummaryOptions();
    const uint8_t source_raw[MAC_LENGTH] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};

    ours.local_macs.push_back(mac_from_bytes(source_raw));

    PacketSummary mine = summarize_packet(decode_packet(frame, sizeof(frame)), 0, 0, ours);

    CHECK(mine.line.find("somme calculee par la carte") != std::string::npos);
    CHECK(mine.line.find("somme TCP invalide") == std::string::npos);

    // Cas 3: on connait nos adresses, mais celle-ci n'en fait pas partie.
    // Le paquet vient donc vraiment d'ailleurs: on le signale.
    SummaryOptions others = SummaryOptions();
    const uint8_t other_raw[MAC_LENGTH] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    others.local_macs.push_back(mac_from_bytes(other_raw));

    PacketSummary foreign = summarize_packet(decode_packet(frame, sizeof(frame)), 0, 0, others);

    CHECK(foreign.line.find("somme TCP invalide") != std::string::npos);
}

// Les paquets malformes doivent etre refuses, et pour la bonne raison.
// Ces chemins de rejet n'etaient testes nulle part.
static void test_rejections(void)
{
    uint8_t frame[sizeof(packet_tcp_syn)];
    Ipv4Header ip;
    TcpHeader tcp;
    UdpHeader udp;

    // Version differente de 4: ce n'est pas de l'IPv4.
    memcpy(frame, packet_tcp_syn, sizeof(frame));
    frame[14] = 0x65;                     // version 6, taille 5
    CHECK(parse_ipv4(frame, sizeof(frame), 14, &ip) == false);

    // Taille d'en-tete annoncee plus petite que le minimum legal de 20 octets.
    memcpy(frame, packet_tcp_syn, sizeof(frame));
    frame[14] = 0x44;                     // version 4, taille 4 mots = 16 octets
    CHECK(parse_ipv4(frame, sizeof(frame), 14, &ip) == false);

    // Longueur totale plus petite que l'en-tete: incoherent.
    memcpy(frame, packet_tcp_syn, sizeof(frame));
    frame[16] = 0x00;
    frame[17] = 0x0a;                     // 10 octets annonces, en-tete de 20
    CHECK(parse_ipv4(frame, sizeof(frame), 14, &ip) == false);

    // En-tete TCP annonce plus petit que le minimum legal.
    memcpy(frame, packet_tcp_syn, sizeof(frame));
    frame[46] = 0x40;                     // 4 mots au lieu de 5
    CHECK(parse_tcp(frame, sizeof(frame), 34, 20,
                    ipv4_from_bytes(frame + 26), ipv4_from_bytes(frame + 30),
                    &tcp) == false);

    // Longueur UDP plus petite que son propre en-tete de 8 octets.
    uint8_t udp_frame[sizeof(packet_udp_dns)];

    memcpy(udp_frame, packet_udp_dns, sizeof(udp_frame));
    udp_frame[38] = 0x00;
    udp_frame[39] = 0x03;                 // 3 octets annonces
    CHECK(parse_udp(udp_frame, sizeof(udp_frame), 34,
                    ipv4_from_bytes(udp_frame + 26), ipv4_from_bytes(udp_frame + 30),
                    &udp) == false);

    // Un paquet sans aucun drapeau doit le dire, pas rendre une chaine vide.
    memcpy(frame, packet_tcp_syn, sizeof(frame));
    frame[47] = 0x00;
    CHECK(parse_tcp(frame, sizeof(frame), 34, 20,
                    ipv4_from_bytes(frame + 26), ipv4_from_bytes(frame + 30),
                    &tcp) == true);
    CHECK(tcp_flags_string(tcp) == "aucun");

    // Les noms des types Ethernet, y compris le repli sur le chiffre.
    CHECK(std::string(ethertype_name(ETHERTYPE_ARP)) == "ARP");
    CHECK(std::string(ethertype_name(ETHERTYPE_IPV6)) == "IPv6");
    CHECK(std::string(ethertype_name(ETHERTYPE_VLAN)) == "VLAN");
    CHECK(std::string(ethertype_name(0x1234)) == "0x1234");
}

void test_dissect(void)
{
    printf("dissect\n");

    // ---------------------------------------------------------- Ethernet
    EthernetHeader eth;

    CHECK(parse_ethernet(packet_tcp_syn, sizeof(packet_tcp_syn), &eth) == true);
    CHECK(mac_to_string(eth.destination) == "c8:5e:a9:53:40:3a");
    CHECK(mac_to_string(eth.source) == "00:1a:2b:3c:4d:5e");
    CHECK(eth.type == ETHERTYPE_IPV4);
    CHECK(eth.payload_offset == 14);
    CHECK(std::string(ethertype_name(eth.type)) == "IPv4");

    // Une trame trop courte ne doit pas etre decodee, et surtout pas planter.
    for (size_t cut = 0; cut < 14; cut++)
        CHECK(parse_ethernet(packet_tcp_syn, cut, &eth) == false);

    // L'etiquette VLAN doit etre sautee, et le vrai type retrouve derriere.
    EthernetHeader tagged;

    CHECK(parse_ethernet(packet_vlan, sizeof(packet_vlan), &tagged) == true);
    CHECK(tagged.type == ETHERTYPE_IPV4);
    CHECK(tagged.payload_offset == 18);  // 14 + 4 octets d'etiquette

    // --------------------------------------------------------------- ARP
    EthernetHeader arp_eth;
    ArpHeader arp;

    CHECK(parse_ethernet(packet_arp_request, sizeof(packet_arp_request), &arp_eth) == true);
    CHECK(arp_eth.type == ETHERTYPE_ARP);
    CHECK(parse_arp(packet_arp_request, sizeof(packet_arp_request),
                    arp_eth.payload_offset, &arp) == true);
    CHECK(arp.operation == ARP_REQUEST);
    CHECK(std::string(arp_operation_name(arp.operation)) == "request");
    CHECK(mac_to_string(arp.sender_mac) == "c8:5e:a9:53:40:3a");
    CHECK(ipv4_to_string(arp.sender_ip) == "192.168.1.10");
    CHECK(ipv4_to_string(arp.target_ip) == "192.168.1.1");

    // Un paquet qui annonce une taille d'adresse differente n'est pas de
    // l'ARP Ethernet/IPv4: on le refuse plutot que de lire une adresse fausse.
    uint8_t bad_arp[sizeof(packet_arp_request)];

    memcpy(bad_arp, packet_arp_request, sizeof(bad_arp));
    bad_arp[18] = 8;  // hardware_length devient 8 au lieu de 6
    ArpHeader ignored_arp;
    CHECK(parse_arp(bad_arp, sizeof(bad_arp), arp_eth.payload_offset, &ignored_arp) == false);

    // Tronquer la trame a n'importe quel endroit ne doit jamais planter.
    for (size_t cut = 0; cut < sizeof(packet_arp_request); cut++) {
        ArpHeader ignored;

        parse_arp(packet_arp_request, cut, arp_eth.payload_offset, &ignored);
    }

    // Decode_packet doit suivre la meme branche et s'arreter la: une trame
    // ARP n'a pas d'en-tete IPv4.
    DecodedPacket decoded_arp = decode_packet(packet_arp_request, sizeof(packet_arp_request));
    CHECK(decoded_arp.has_ethernet == true);
    CHECK(decoded_arp.has_arp == true);
    CHECK(decoded_arp.has_ipv4 == false);
    CHECK(decoded_arp.arp.operation == ARP_REQUEST);

    // -------------------------------------------------------------- IPv4
    Ipv4Header ip;

    CHECK(parse_ipv4(packet_tcp_syn, sizeof(packet_tcp_syn),
                     eth.payload_offset, &ip) == true);
    CHECK(ip.version == 4);
    CHECK(ip.header_length == 20);
    CHECK(ip.total_length == 40);
    CHECK(ip.ttl == 64);
    CHECK(ip.protocol == IP_PROTOCOL_TCP);
    CHECK(ipv4_to_string(ip.source) == "192.168.1.10");
    CHECK(ipv4_to_string(ip.destination) == "93.184.216.34");
    CHECK(ip.checksum_valid == true);
    CHECK(ip.dont_fragment == true);
    CHECK(ip.identification == 0x1c46);
    CHECK(ip.more_fragments == false);
    CHECK(ipv4_is_fragment(ip) == false);
    CHECK(ipv4_has_transport_header(ip) == true);
    CHECK(ip.payload_offset == 34);
    CHECK(ip.payload_length == 20);
    CHECK(std::string(ip_protocol_name(ip.protocol)) == "TCP");

    // Un seul octet modifie dans l'en-tete doit casser la somme de controle.
    uint8_t damaged[sizeof(packet_tcp_syn)];

    memcpy(damaged, packet_tcp_syn, sizeof(packet_tcp_syn));
    damaged[26] ^= 0x01;  // un bit de l'adresse source
    Ipv4Header broken;
    CHECK(parse_ipv4(damaged, sizeof(damaged), 14, &broken) == true);
    CHECK(broken.checksum_valid == false);

    // Tronquer le paquet a n'importe quel endroit ne doit jamais planter.
    for (size_t cut = 0; cut < sizeof(packet_tcp_syn); cut++) {
        Ipv4Header ignored;

        parse_ipv4(packet_tcp_syn, cut, 14, &ignored);
    }

    // --------------------------------------------------------------- TCP
    TcpHeader tcp;

    CHECK(parse_tcp(packet_tcp_syn, sizeof(packet_tcp_syn), ip.payload_offset,
                    ip.payload_length, ip.source, ip.destination, &tcp) == true);
    CHECK(tcp.source_port == 54321);
    CHECK(tcp.destination_port == 80);
    CHECK(tcp.sequence == 0x12345678);
    CHECK(tcp.header_length == 20);
    CHECK(tcp.syn == true);
    CHECK(tcp.ack == false);
    CHECK(tcp.fin == false);
    CHECK(tcp.rst == false);
    CHECK(tcp.window == 64240);
    // Les numeros de sequence et d'acquittement servent au moteur d'analyse,
    // qui reperera les paquets reemis. On verifie ici qu'ils sont bien lus.
    CHECK(tcp.acknowledgment == 0);
    CHECK(tcp.checksum_valid == true);
    CHECK(tcp.payload_length == 0);
    CHECK(tcp_flags_string(tcp) == "SYN");

    for (size_t cut = 0; cut < sizeof(packet_tcp_syn); cut++) {
        TcpHeader ignored;

        parse_tcp(packet_tcp_syn, cut, 34, 20, ip.source, ip.destination, &ignored);
    }

    // --------------------------------------------------------------- UDP
    EthernetHeader eth2;
    Ipv4Header ip2;
    UdpHeader udp;

    CHECK(parse_ethernet(packet_udp_dns, sizeof(packet_udp_dns), &eth2) == true);
    CHECK(parse_ipv4(packet_udp_dns, sizeof(packet_udp_dns),
                     eth2.payload_offset, &ip2) == true);
    CHECK(ip2.protocol == IP_PROTOCOL_UDP);
    CHECK(ip2.checksum_valid == true);
    CHECK(ipv4_to_string(ip2.destination) == "8.8.8.8");

    CHECK(parse_udp(packet_udp_dns, sizeof(packet_udp_dns), ip2.payload_offset,
                    ip2.source, ip2.destination, &udp) == true);
    CHECK(udp.source_port == 51000);
    CHECK(udp.destination_port == 53);
    CHECK(udp.length == 41);  // 8 octets d'en-tete + 33 de requete DNS
    CHECK(udp.has_checksum == true);
    CHECK(udp.checksum_valid == true);
    CHECK(udp.payload_length == 33);

    for (size_t cut = 0; cut < sizeof(packet_udp_dns); cut++) {
        UdpHeader ignored;

        parse_udp(packet_udp_dns, cut, 34, ip2.source, ip2.destination, &ignored);
    }

    // -------------------------------------------------------------- ICMP
    EthernetHeader eth3;
    Ipv4Header ip3;
    IcmpHeader icmp;

    CHECK(parse_ethernet(packet_icmp_echo, sizeof(packet_icmp_echo), &eth3) == true);
    CHECK(parse_ipv4(packet_icmp_echo, sizeof(packet_icmp_echo),
                     eth3.payload_offset, &ip3) == true);
    CHECK(ip3.protocol == IP_PROTOCOL_ICMP);
    CHECK(ip3.checksum_valid == true);

    CHECK(parse_icmp(packet_icmp_echo, sizeof(packet_icmp_echo), ip3.payload_offset,
                     ip3.payload_length, &icmp) == true);
    CHECK(icmp.type == ICMP_ECHO_REQUEST);
    CHECK(std::string(icmp_type_name(icmp.type)) == "echo request");
    CHECK(icmp.has_echo == true);
    CHECK(icmp.echo_identifier == 0x1234);
    CHECK(icmp.echo_sequence == 1);
    CHECK(icmp.payload_length == 4);
    CHECK(icmp.checksum_valid == true);

    // Un seul octet modifie doit casser la somme de controle, comme pour
    // les autres protocoles.
    uint8_t damaged_icmp[sizeof(packet_icmp_echo)];

    memcpy(damaged_icmp, packet_icmp_echo, sizeof(damaged_icmp));
    damaged_icmp[sizeof(damaged_icmp) - 1] ^= 0x01;
    IcmpHeader broken_icmp;
    CHECK(parse_icmp(damaged_icmp, sizeof(damaged_icmp), ip3.payload_offset,
                     ip3.payload_length, &broken_icmp) == true);
    CHECK(broken_icmp.checksum_valid == false);

    for (size_t cut = 0; cut < sizeof(packet_icmp_echo); cut++) {
        IcmpHeader ignored;

        parse_icmp(packet_icmp_echo, cut, 34, ip3.payload_length, &ignored);
    }

    DecodedPacket decoded_icmp = decode_packet(packet_icmp_echo, sizeof(packet_icmp_echo));
    CHECK(decoded_icmp.has_ipv4 == true);
    CHECK(decoded_icmp.has_icmp == true);
    CHECK(decoded_icmp.icmp.type == ICMP_ECHO_REQUEST);

    // Les numeros de protocole doivent avoir un nom lisible.
    CHECK(std::string(ip_protocol_name(IP_PROTOCOL_ICMP)) == "ICMP");
    CHECK(std::string(ip_protocol_name(IP_PROTOCOL_IGMP)) == "IGMP");
    CHECK(std::string(ip_protocol_name(IP_PROTOCOL_TCP)) == "TCP");
    CHECK(std::string(ip_protocol_name(IP_PROTOCOL_UDP)) == "UDP");
    CHECK(std::string(ip_protocol_name(IP_PROTOCOL_GRE)) == "GRE");
    CHECK(std::string(ip_protocol_name(IP_PROTOCOL_OSPF)) == "OSPF");
    // Un numero inconnu doit se rabattre sur le chiffre, pas sur du vide.
    CHECK(std::string(ip_protocol_name(200)) == "200");

    test_edge_cases();
    test_hardware_assembly();
    test_truncated_no_false_alarm();
    test_own_packets_checksum();
    test_rejections();

    // ------------------------------------------------- somme de controle
    // Une zone dont la somme est deja juste doit se verifier a zero.
    const uint8_t header[20] = {
        0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
        0x26, 0xfd, 0xc0, 0xa8, 0x01, 0x0a, 0x5d, 0xb8, 0xd8, 0x22};

    CHECK(internet_checksum(header, sizeof(header)) == 0);

    // ------------------------------------------------------ ligne resumee
    // La ligne affichee doit contenir les informations essentielles.
    std::string line = summarize_packet(decode_packet(packet_tcp_syn, sizeof(packet_tcp_syn)), 0, 0,
                                        SummaryOptions()).line;

    CHECK(line.find("192.168.1.10:54321") != std::string::npos);
    CHECK(line.find("93.184.216.34:80") != std::string::npos);
    CHECK(line.find("TCP") != std::string::npos);
    CHECK(line.find("SYN") != std::string::npos);
    // Les sommes de controle sont bonnes: aucune alerte ne doit apparaitre.
    CHECK(line.find("invalide") == std::string::npos);

    std::string udp_line = summarize_packet(decode_packet(packet_udp_dns, sizeof(packet_udp_dns)), 0, 0,
                                        SummaryOptions()).line;

    CHECK(udp_line.find("8.8.8.8:53") != std::string::npos);
    CHECK(udp_line.find("UDP") != std::string::npos);
    CHECK(udp_line.find("33 octets") != std::string::npos);

    // Un paquet abime doit etre signale, pas cache.
    std::string damaged_line = summarize_packet(decode_packet(damaged, sizeof(damaged)), 0, 0,
                                        SummaryOptions()).line;

    CHECK(damaged_line.find("somme IP invalide") != std::string::npos);

    // Le point le plus important: quelle que soit la facon dont on coupe un
    // paquet, la fonction doit rendre une ligne et ne jamais planter.
    for (size_t cut = 0; cut <= sizeof(packet_tcp_syn); cut++) {
        std::string cut_line = summarize_packet(decode_packet(packet_tcp_syn, cut), 0, 0,
                                        SummaryOptions()).line;

        CHECK(cut_line.empty() == false);
    }
    for (size_t cut = 0; cut <= sizeof(packet_udp_dns); cut++)
        summarize_packet(decode_packet(packet_udp_dns, cut), 0, 0,
                                        SummaryOptions());
    for (size_t cut = 0; cut <= sizeof(packet_vlan); cut++)
        summarize_packet(decode_packet(packet_vlan, cut), 0, 0,
                                        SummaryOptions());
}

// Les tests du filtre ont besoin des memes trames. On les leur donne ici
// plutot que de les recopier dans un second fichier.
const uint8_t *filter_test_tcp_frame(size_t *size)
{
    *size = sizeof(packet_tcp_syn);
    return packet_tcp_syn;
}

const uint8_t *filter_test_udp_frame(size_t *size)
{
    *size = sizeof(packet_udp_dns);
    return packet_udp_dns;
}
