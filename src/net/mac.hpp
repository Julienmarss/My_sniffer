#pragma once

#include <stdint.h>

#include <string>

// Longueur d'une adresse MAC. Elle vaut 6 pour Ethernet et pour toutes les
// technologies que ce projet rencontre.
const int MAC_LENGTH = 6;

// Une adresse MAC: l'adresse physique d'une carte reseau.
// Exemple: c8:5e:a9:53:40:3a
struct Mac {
    uint8_t bytes[MAC_LENGTH];
};

// Construit une adresse a partir de 6 octets bruts lus dans un paquet.
Mac mac_from_bytes(const uint8_t *data);

// Ecrit l'adresse en texte, en minuscules, separee par des ":".
std::string mac_to_string(Mac mac);

// Compare deux adresses. Sert a reconnaitre nos propres paquets.
bool operator==(const Mac &a, const Mac &b);

// Les deux predicats suivants ne sont pas encore utilises par l'affichage.
// Ils sont ecrits et testes maintenant parce que le filtrage et le moteur
// d'analyse en auront besoin: reconnaitre une trame de diffusion est le
// premier signe qu'on cherche quand on traque un balayage du reseau.

// Vrai si c'est l'adresse de diffusion ff:ff:ff:ff:ff:ff,
// celle qui vise toutes les machines du reseau local.
bool mac_is_broadcast(Mac mac);

// Vrai si c'est une adresse de groupe (multicast).
// La norme IEEE 802 reserve pour ca le bit de poids faible du premier octet.
bool mac_is_multicast(Mac mac);
