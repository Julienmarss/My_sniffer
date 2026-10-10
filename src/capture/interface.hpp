#pragma once

#include <string>
#include <vector>

#include "net/ipv4_address.hpp"
#include "net/mac.hpp"

// Une adresse IPv4 attachee a une interface, avec la taille de son reseau.
struct InterfaceAddress {
    Ipv4 ip;
    int prefix_length;  // -1 si le masque est absent ou invalide
};

// Une carte reseau telle que le systeme la decrit.
struct Interface {
    std::string name;                        // "eth0", "wlo1", "lo"...
    unsigned index;                          // numero attribue par le systeme
    bool has_mac;                            // certaines interfaces n'ont pas de MAC
    Mac mac;
    std::vector<InterfaceAddress> addresses;
    bool is_up;                              // interface activee
    bool is_running;                         // cable branche ou wifi connecte
    bool is_loopback;                        // c'est "lo", la boucle locale
};

// Liste toutes les interfaces du systeme.
// Ne demande aucun privilege particulier.
// Si une erreur systeme survient, renvoie une liste vide et ecrit le message
// dans "error" (qui peut valoir NULL si l'appelant ne veut pas le detail).
std::vector<Interface> list_interfaces(std::string *error);

// Vrai si cette interface est un choix valable pour capturer du trafic.
// On exclut la boucle locale: elle ne transporte que le trafic de la machine
// avec elle-meme, jamais du trafic exterieur.
bool interface_is_capturable(const Interface &iface);
