#pragma once

#include <stddef.h>
#include <stdint.h>

#include "net/ipv4_address.hpp"

// Somme de controle Internet, definie par la RFC 1071.
// C'est celle qu'utilisent IPv4, ICMP, TCP et UDP.
//
// Le principe: on additionne toute la zone deux octets par deux octets comme
// des nombres de 16 bits, on replie les retenues qui depassent, et on inverse
// tous les bits du resultat.
//
// Pour VERIFIER un en-tete recu, on appelle cette fonction sur l'en-tete
// complet, champ de somme inclus. Si l'en-tete est intact, le resultat vaut 0.
uint16_t internet_checksum(const uint8_t *data, size_t size);

// Les deux fonctions ci-dessous decoupent le calcul en deux temps, pour
// pouvoir additionner plusieurs zones separees. TCP et UDP en ont besoin:
// leur somme couvre un pseudo en-tete fabrique, puis le segment lui-meme.
//
// Attention: n'enchainez que des zones de taille paire, sinon le decoupage
// en paires d'octets se decale et le resultat est faux.

// Additionne une zone, sans replier les retenues ni inverser les bits.
uint32_t checksum_add(const uint8_t *data, size_t size);

// Termine le calcul: replie les retenues et inverse les bits.
uint16_t checksum_finish(uint32_t sum);

// Le pseudo en-tete de TCP et UDP (RFC 793 et RFC 768). Ce n'est pas envoye
// sur le reseau: c'est une zone fabriquee pour le calcul, qui contient les
// deux adresses IP, le protocole et la longueur.
//
// Son role est de detecter un paquet livre au mauvais destinataire: si une
// adresse a ete abimee, la somme ne tombe plus juste.
uint32_t pseudo_header_sum(Ipv4 source, Ipv4 destination,
                           uint8_t protocol, uint16_t length);
