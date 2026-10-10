#include "net/checksum.hpp"

uint32_t checksum_add(const uint8_t *data, size_t size)
{
    uint32_t sum = 0;
    size_t i = 0;

    // On additionne deux octets a la fois, poids fort en premier.
    // On accumule dans un entier de 32 bits pour ne rien perdre en route.
    while (i + 1 < size) {
        sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]);
        i += 2;
    }

    // S'il reste un octet tout seul a la fin, on le complete avec un zero.
    if (i < size)
        sum += static_cast<uint32_t>(data[i] << 8);

    return sum;
}

uint16_t checksum_finish(uint32_t sum)
{
    // On replie les retenues qui ont depasse les 16 bits, jusqu'a ce qu'il
    // n'en reste plus. En pratique deux tours suffisent toujours.
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
}

uint16_t internet_checksum(const uint8_t *data, size_t size)
{
    return checksum_finish(checksum_add(data, size));
}

uint32_t pseudo_header_sum(Ipv4 source, Ipv4 destination,
                           uint8_t protocol, uint16_t length)
{
    // Le pseudo en-tete fait 12 octets:
    //   4 pour l'adresse source, 4 pour la destination,
    //   1 octet a zero, 1 pour le protocole, 2 pour la longueur.
    uint8_t buffer[12];

    for (int i = 0; i < 4; i++) {
        buffer[i] = source.bytes[i];
        buffer[4 + i] = destination.bytes[i];
    }
    buffer[8] = 0;
    buffer[9] = protocol;
    buffer[10] = static_cast<uint8_t>(length >> 8);
    buffer[11] = static_cast<uint8_t>(length & 0xff);

    return checksum_add(buffer, sizeof(buffer));
}
