#pragma once

#include <stddef.h>
#include <stdint.h>

#include "dissect/arp.hpp"
#include "dissect/ethernet.hpp"
#include "dissect/icmp.hpp"
#include "dissect/ipv4.hpp"
#include "dissect/tcp.hpp"
#include "dissect/udp.hpp"

// Tout ce qu'on a compris d'un paquet, une fois ses en-tetes decodes.
//
// Un paquet brut est une suite d'octets. Cette structure, c'est le meme
// paquet apres lecture: on sait quelles couches il contient et ce qu'elles
// disent. Les drapeaux "has_" disent jusqu'ou on a pu aller.
//
// On decode UNE FOIS par paquet, puis tout le monde se sert de ce resultat:
// l'affichage, le filtre, et plus tard le moteur d'analyse. Sans ca, chacun
// relirait les memes octets de son cote.
struct DecodedPacket {
    size_t frame_length;   // taille totale de ce qu'on a recu

    bool has_ethernet;
    EthernetHeader ethernet;

    bool has_ipv4;
    Ipv4Header ipv4;

    bool has_arp;
    ArpHeader arp;

    // Un paquet decoupe en morceaux ne porte son en-tete TCP ou UDP que dans
    // son premier morceau: has_tcp et has_udp sont alors faux sur les suivants.
    bool has_tcp;
    TcpHeader tcp;

    bool has_udp;
    UdpHeader udp;

    bool has_icmp;
    IcmpHeader icmp;
};

// Decode un paquet brut. Ne echoue jamais: si le paquet est trop court ou
// incoherent, les drapeaux "has_" disent simplement jusqu'ou on a pu lire.
DecodedPacket decode_packet(const uint8_t *data, size_t size);
