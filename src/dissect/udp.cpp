#include "dissect/udp.hpp"

#include "net/bytes.hpp"
#include "net/checksum.hpp"

bool parse_udp(const uint8_t *data, size_t size, size_t offset,
               Ipv4 source_ip, Ipv4 destination_ip, UdpHeader *out)
{
    // L'en-tete UDP fait exactement 8 octets, toujours.
    if (!has_bytes(size, offset, 8))
        return false;

    out->source_port = read_u16(data, offset);
    out->destination_port = read_u16(data, offset + 2);
    out->length = read_u16(data, offset + 4);

    uint16_t checksum = read_u16(data, offset + 6);

    // La longueur annoncee compte l'en-tete, donc elle vaut au moins 8.
    // Moins que ca, le paquet est casse.
    if (out->length < 8)
        return false;

    out->payload_offset = offset + 8;
    out->payload_length = out->length - 8;

    // On ne garde que ce qu'on a vraiment recu.
    size_t available = size - out->payload_offset;

    if (out->payload_length > available)
        out->payload_length = available;

    // En IPv4, la somme de controle est facultative: une valeur de zero
    // signifie "je ne l'ai pas calculee". C'est different d'une somme fausse.
    out->has_checksum = checksum != 0;
    out->checksum_valid = false;

    if (out->has_checksum && has_bytes(size, offset, out->length)) {
        uint32_t sum = pseudo_header_sum(source_ip, destination_ip, 17, out->length);

        sum += checksum_add(data + offset, out->length);
        out->checksum_valid = checksum_finish(sum) == 0;
    }

    return true;
}
