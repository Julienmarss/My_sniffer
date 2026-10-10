#include "net/ipv4_address.hpp"

#include <stdio.h>

Ipv4 ipv4_from_bytes(const uint8_t *data)
{
    Ipv4 ip;

    for (int i = 0; i < 4; i++)
        ip.bytes[i] = data[i];
    return ip;
}

std::string ipv4_to_string(Ipv4 ip)
{
    char text[16];  // "255.255.255.255" + le zero final

    snprintf(text, sizeof(text), "%u.%u.%u.%u",
             ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3]);
    return std::string(text);
}

bool ipv4_is_loopback(Ipv4 ip)
{
    return ip.bytes[0] == 127;
}

bool ipv4_is_private(Ipv4 ip)
{
    // 10.0.0.0/8 : tout ce qui commence par 10.
    if (ip.bytes[0] == 10)
        return true;

    // 172.16.0.0/12 : de 172.16.x.x a 172.31.x.x.
    if (ip.bytes[0] == 172 && ip.bytes[1] >= 16 && ip.bytes[1] <= 31)
        return true;

    // 192.168.0.0/16 : tout ce qui commence par 192.168.
    if (ip.bytes[0] == 192 && ip.bytes[1] == 168)
        return true;

    return false;
}

bool ipv4_is_link_local(Ipv4 ip)
{
    return ip.bytes[0] == 169 && ip.bytes[1] == 254;
}

bool ipv4_is_multicast(Ipv4 ip)
{
    // De 224.0.0.0 a 239.255.255.255.
    return ip.bytes[0] >= 224 && ip.bytes[0] <= 239;
}

bool ipv4_is_broadcast(Ipv4 ip)
{
    return ipv4_to_uint(ip) == 0xffffffffu;
}

bool ipv4_is_public(Ipv4 ip)
{
    // 0.0.0.0 veut dire "aucune adresse", par exemple dans une demande DHCP
    // faite avant d'en avoir une.
    if (ip.bytes[0] == 0)
        return false;

    return !ipv4_is_private(ip) && !ipv4_is_loopback(ip) && !ipv4_is_multicast(ip)
        && !ipv4_is_link_local(ip) && !ipv4_is_broadcast(ip);
}

bool ipv4_in_network(Ipv4 address, Ipv4 prefix, int length)
{
    if (length <= 0)
        return true;     // /0 designe le reseau entier
    if (length > 32)
        return false;

    // Le masque a "length" bits a un, puis des zeros. Le decalage de 32 bits
    // n'etant pas defini en C++, le cas /32 est traite a part.
    uint32_t mask = (length == 32) ? 0xffffffffu : ~(0xffffffffu >> length);

    return (ipv4_to_uint(address) & mask) == (ipv4_to_uint(prefix) & mask);
}

int ipv4_prefix_length(Ipv4 mask)
{
    int length = 0;
    int i = 0;

    // Un masque valide est une suite de 1 suivie d'une suite de 0.
    // On compte d'abord les 1.
    while (i < 32) {
        int byte = i / 8;
        int bit = 7 - (i % 8);

        if ((mask.bytes[byte] & (1 << bit)) == 0)
            break;
        length++;
        i++;
    }

    // Puis on verifie que tout le reste est bien a zero.
    while (i < 32) {
        int byte = i / 8;
        int bit = 7 - (i % 8);

        if ((mask.bytes[byte] & (1 << bit)) != 0)
            return -1;
        i++;
    }

    return length;
}

bool ipv4_from_string(const std::string &text, Ipv4 *ip)
{
    int values[4] = {0, 0, 0, 0};
    int part = 0;
    int digits = 0;

    for (size_t i = 0; i < text.size(); i++) {
        char c = text[i];

        if (c == '.') {
            // Un point doit suivre au moins un chiffre, et il n'y en a que trois.
            if (digits == 0 || part >= 3)
                return false;
            part++;
            digits = 0;
            continue;
        }
        if (c < '0' || c > '9')
            return false;

        values[part] = values[part] * 10 + (c - '0');
        digits++;
        // Trois chiffres au maximum, et jamais plus de 255.
        if (digits > 3 || values[part] > 255)
            return false;
    }

    // Il faut exactement quatre nombres, et le dernier ne doit pas etre vide.
    if (part != 3 || digits == 0)
        return false;

    for (int i = 0; i < 4; i++)
        ip->bytes[i] = static_cast<uint8_t>(values[i]);
    return true;
}

uint32_t ipv4_to_uint(Ipv4 ip)
{
    return (static_cast<uint32_t>(ip.bytes[0]) << 24)
         | (static_cast<uint32_t>(ip.bytes[1]) << 16)
         | (static_cast<uint32_t>(ip.bytes[2]) << 8)
         |  static_cast<uint32_t>(ip.bytes[3]);
}

bool operator==(const Ipv4 &a, const Ipv4 &b)
{
    for (int i = 0; i < 4; i++) {
        if (a.bytes[i] != b.bytes[i])
            return false;
    }
    return true;
}

bool operator<(const Ipv4 &a, const Ipv4 &b)
{
    return ipv4_to_uint(a) < ipv4_to_uint(b);
}
