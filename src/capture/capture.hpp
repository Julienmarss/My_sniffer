#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "net/packet.hpp"

// Une session de capture ouverte sur une interface.
//
// L'implementation change selon le systeme: capture_linux.cpp utilise une
// socket AF_PACKET, capture_bsd.cpp utilise le peripherique bpf,
// capture_windows.cpp utilise Npcap (seule facon d'obtenir la trame
// Ethernet complete sous Windows, voir docs/PRIVILEGES.md).
struct Capture {
    int fd;                        // le descripteur ouvert sur le systeme
    std::vector<uint8_t> buffer;   // la ou le systeme depose les paquets

    // Utilises seulement par la version BSD, qui recoit plusieurs paquets
    // d'un coup et doit se souvenir ou elle en est dans le tampon.
    size_t buffer_used;
    size_t buffer_position;

    // Utilise seulement par la version Windows: Npcap manipule un pcap_t*,
    // pas un descripteur entier. "fd" reste a -1 sur ce systeme.
    void *handle = nullptr;
};

// Ouvre une capture sur l'interface donnee.
//
// Demande des privileges: root, ou la capacite adequate. Voir docs/PRIVILEGES.md.
// En cas d'echec, retourne false et ecrit la raison dans "error".
bool capture_open(Capture *capture, const std::string &interface_name,
                  bool promiscuous, std::string *error);

// Attend le prochain paquet et le decrit dans "packet".
//
// Bloque jusqu'a ce qu'un paquet arrive. Retourne false dans deux cas qu'il
// faut distinguer:
//   - une vraie erreur: "error" contient la raison;
//   - une interruption par un signal, un Ctrl+C par exemple: "error" est VIDE.
// L'appelant regarde donc si le message est vide avant de crier a la panne.
bool capture_next(Capture *capture, CapturedPacket *packet, std::string *error);

// Ferme la session. A n'appeler qu'apres un capture_open reussi:
// une structure Capture jamais ouverte contient n'importe quoi.
void capture_close(Capture *capture);

// Nombre de paquets que le systeme a du jeter faute de place.
// C'est l'indicateur qui dit si le programme n'arrive plus a suivre.
// Retourne 0 si le systeme ne sait pas le dire.
unsigned long capture_dropped(Capture *capture);
