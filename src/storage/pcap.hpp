#pragma once

#include <stdio.h>

#include <string>
#include <vector>

#include "net/packet.hpp"

// Lecture et ecriture de fichiers .pcap.
//
// C'est le format historique de tcpdump et de Wireshark. Il est volontairement
// minuscule: un en-tete de 24 octets au debut du fichier, puis pour chaque
// paquet un en-tete de 16 octets suivi des octets bruts du paquet.
//
//   +---------------------------+
//   | en-tete de fichier, 24 o. |
//   +---------------------------+
//   | en-tete de paquet, 16 o.  |
//   | octets du paquet          |
//   +---------------------------+
//   | en-tete de paquet, 16 o.  |
//   | octets du paquet          |
//   +---------------------------+
//   | ...                       |
//
// Pourquoi ce format et pas son successeur pcapng: pcapng est bien plus riche
// mais aussi bien plus gros a implementer (blocs, options, plusieurs
// interfaces). Le format classique suffit a tout ce que le sujet demande, et
// tous les outils le lisent. On pourra ajouter pcapng plus tard sans rien
// casser, puisque la lecture et l'ecriture sont isolees dans ce fichier.

// Type de liaison: 1 signifie Ethernet. La liste est tenue par tcpdump.org.
const uint32_t PCAP_LINKTYPE_ETHERNET = 1;

// Une session d'ecriture.
struct PcapWriter {
    FILE *file;
    unsigned long written;  // nombre de paquets ecrits
};

// Cree le fichier et y ecrit l'en-tete.
bool pcap_writer_open(PcapWriter *writer, const std::string &path, std::string *error);

// Ajoute un paquet au fichier.
// "length" est ce qu'on a capture, "original_length" la taille sur le cable.
bool pcap_writer_write(PcapWriter *writer, const uint8_t *data, size_t length,
                       size_t original_length, long seconds, long microseconds,
                       std::string *error);

void pcap_writer_close(PcapWriter *writer);

// Une session de lecture.
struct PcapReader {
    FILE *file;
    bool swapped;      // le fichier vient d'une machine a l'ordre inverse
    bool nanoseconds;  // les dates sont en nanosecondes et non en microsecondes
    uint32_t snaplen;  // taille maximale capturee, annoncee par le fichier
    uint32_t linktype; // PCAP_LINKTYPE_ETHERNET, normalement
    std::vector<uint8_t> buffer;
};

// Ouvre le fichier et lit son en-tete.
// Echoue si ce n'est pas un fichier pcap ou si le type de liaison n'est pas
// gere. Le message d'erreur dit lequel des deux.
bool pcap_reader_open(PcapReader *reader, const std::string &path, std::string *error);

// Lit le paquet suivant.
//
// Retourne true et remplit "packet" tant qu'il en reste.
// A la fin du fichier, retourne true avec "end" mis a true.
// Retourne false seulement en cas de vrai probleme.
bool pcap_reader_next(PcapReader *reader, CapturedPacket *packet,
                      bool *end, std::string *error);

void pcap_reader_close(PcapReader *reader);
