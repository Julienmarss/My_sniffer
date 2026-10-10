#pragma once

#include <string>
#include <vector>

#include "dissect/decode.hpp"
#include "net/mac.hpp"
#include "term/color.hpp"

// Reglages de l'affichage.
struct SummaryOptions {
    // Les adresses des cartes reseau de cette machine, quand on les connait.
    //
    // Elles servent a reconnaitre les paquets que la machine EMET, ce qui
    // change ce qu'on dit de leur somme de controle. Sur du materiel moderne,
    // la carte calcule elle-meme la somme au tout dernier moment, une fois le
    // paquet deja capture: le champ est donc encore vide quand on le lit.
    // Sans cette reconnaissance, le programme crierait a l'erreur sur chaque
    // paquet sortant. On appelle ce mecanisme le "checksum offloading".
    //
    // La liste est vide quand on relit un fichier venu d'ailleurs: on ne peut
    // alors rien affirmer sur la provenance des paquets.
    std::vector<Mac> local_macs;

    // Les couleurs a employer. Par defaut la palette est vide, donc la ligne
    // sort en texte brut: c'est ce que veulent les tests et les fichiers.
    Palette palette;
};

// Ce que le resume a produit.
struct PacketSummary {
    std::string line;        // la ligne a afficher
    bool checksum_problem;   // au moins une somme de controle ne tombe pas juste
};

// Resume un paquet en une seule ligne lisible, dans l'esprit de tcpdump.
//
// Les champs sont completes avec des espaces pour tomber toujours a la meme
// colonne. Sans ca, la moindre difference de longueur d'adresse decale tout et
// l'oeil ne peut plus suivre une colonne sur des centaines de lignes.
//
// Exemple de sortie reelle:
//   23:13:20.000000  00:1a:2b:3c:4d:5e > c8:5e:a9:53:40:3a  192.168.1.10:54321    > 93.184.216.34:80      TCP   SYN              0 octets
//
// La fonction prend un paquet DEJA decode: elle se contente de le mettre en
// mots. C'est ce qui garantit que l'affichage, le filtre et l'analyse parlent
// tous du meme decodage, fait une seule fois.
PacketSummary summarize_packet(const DecodedPacket &packet, long seconds, long microseconds,
                               const SummaryOptions &options);
