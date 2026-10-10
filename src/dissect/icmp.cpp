#include "dissect/icmp.hpp"

#include "net/bytes.hpp"
#include "net/checksum.hpp"

bool parse_icmp(const uint8_t *data, size_t size, size_t offset,
                size_t message_length, IcmpHeader *out)
{
    // Les 8 premiers octets sont communs a tous les messages ICMP.
    if (!has_bytes(size, offset, 8))
        return false;

    out->type = read_u8(data, offset);
    out->code = read_u8(data, offset + 1);

    out->has_echo = (out->type == ICMP_ECHO_REQUEST || out->type == ICMP_ECHO_REPLY);
    out->echo_identifier = out->has_echo ? read_u16(data, offset + 4) : 0;
    out->echo_sequence = out->has_echo ? read_u16(data, offset + 6) : 0;

    out->payload_offset = offset + 8;
    out->payload_length = 0;
    if (message_length > 8)
        out->payload_length = message_length - 8;

    // On ne garde que ce qu'on a vraiment recu.
    size_t available = size - out->payload_offset;

    if (out->payload_length > available)
        out->payload_length = available;

    // La somme de controle couvre tout le message ICMP (type, code, somme
    // elle-meme comprise, et les donnees), sans pseudo en-tete contrairement
    // a TCP et UDP. Meme reserve que pour TCP: n'a de sens que si le message
    // est complet, ce que l'appelant sait et nous non. Voir summary.cpp.
    out->checksum_valid = has_bytes(size, offset, message_length)
                        && internet_checksum(data + offset, message_length) == 0;

    return true;
}

const char *icmp_type_name(uint8_t type)
{
    switch (type) {
    case ICMP_ECHO_REPLY:
        return "echo reply";
    case ICMP_DESTINATION_UNREACHABLE:
        return "destination unreachable";
    case ICMP_ECHO_REQUEST:
        return "echo request";
    case ICMP_TIME_EXCEEDED:
        return "time exceeded";
    default:
        return "?";
    }
}
