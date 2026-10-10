#pragma once

#include <stdint.h>

#include <string>

// Une adresse IPv4: 4 octets. Exemple: 192.168.1.10
struct Ipv4 {
    uint8_t bytes[4];
};

// Construit une adresse a partir de 4 octets bruts lus dans un paquet.
Ipv4 ipv4_from_bytes(const uint8_t *data);

// Ecrit l'adresse en texte, par exemple "192.168.1.10".
std::string ipv4_to_string(Ipv4 ip);

// Lit une adresse ecrite en texte, "192.168.1.10" par exemple.
// Retourne false si le texte n'est pas une adresse valide.
bool ipv4_from_string(const std::string &text, Ipv4 *ip);

// L'adresse vue comme un seul nombre de 32 bits, le premier octet en tete.
// Sert a comparer une adresse a un reseau, en masquant les bits inutiles.
uint32_t ipv4_to_uint(Ipv4 ip);

// Compare deux adresses.
bool operator==(const Ipv4 &a, const Ipv4 &b);

// Ordonne deux adresses, pour pouvoir les ranger dans une map.
// L'ordre n'a pas de sens reseau: il sert seulement de cle de tri.
bool operator<(const Ipv4 &a, const Ipv4 &b);

// Les predicats de classification ci-dessous ne sont pas encore utilises par
// l'affichage. Ils sont ecrits et testes maintenant parce que le moteur
// d'analyse en dependra: distinguer une adresse privee d'une adresse publique
// est exactement ce qui permet de reperer une connexion vers l'exterieur.

// 127.0.0.0/8 : la machine elle-meme.
bool ipv4_is_loopback(Ipv4 ip);

// Reseaux prives (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
// Ce sont les adresses qui ne circulent jamais sur Internet.
bool ipv4_is_private(Ipv4 ip);

// 169.254.0.0/16 : adresse que la machine s'attribue seule
// quand aucun serveur DHCP ne repond.
bool ipv4_is_link_local(Ipv4 ip);

// 224.0.0.0/4 : adresses de groupe.
bool ipv4_is_multicast(Ipv4 ip);

// 255.255.255.255 : le message va a toutes les machines du reseau local.
bool ipv4_is_broadcast(Ipv4 ip);

// Vrai si l'adresse peut etre jointe depuis Internet.
//
// C'est la question que se pose le moteur d'analyse: une machine qui parle a
// une adresse publique sort du reseau local. Ne le sont ni les reseaux prives,
// ni la boucle locale, ni les adresses de groupe, ni la diffusion, ni les
// adresses auto-attribuees, ni 0.0.0.0.
bool ipv4_is_public(Ipv4 ip);

// Vrai si l'adresse appartient au reseau decrit par "prefix/length".
//
// Un prefixe de 24 veut dire "les 24 premiers bits doivent etre les memes".
// On compare donc les deux adresses apres avoir mis a zero les bits qui ne
// comptent pas. Une longueur de 0 designe tout Internet.
bool ipv4_in_network(Ipv4 address, Ipv4 prefix, int length);

// Convertit un masque de sous-reseau en longueur de prefixe.
// Exemple: 255.255.255.0 donne 24.
// Retourne -1 si le masque est invalide, c'est-a-dire s'il a des trous
// comme 255.0.255.0, ce qui n'est pas un prefixe valide.
int ipv4_prefix_length(Ipv4 mask);
