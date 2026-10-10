#include "net/bytes.hpp"

bool has_bytes(size_t size, size_t offset, size_t count)
{
    // On ecrit le test comme une soustraction et non comme
    // "offset + count <= size", parce que "offset + count" peut deborder
    // et repasser a zero si offset est enorme. Une lecture hors limites
    // paraitrait alors valide. Un paquet malveillant peut provoquer ca.
    if (offset > size)
        return false;
    return count <= size - offset;
}

uint8_t read_u8(const uint8_t *data, size_t offset)
{
    return data[offset];
}

uint16_t read_u16(const uint8_t *data, size_t offset)
{
    // Octet de poids fort en premier.
    return static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
}

uint32_t read_u32(const uint8_t *data, size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24)
         | (static_cast<uint32_t>(data[offset + 1]) << 16)
         | (static_cast<uint32_t>(data[offset + 2]) << 8)
         |  static_cast<uint32_t>(data[offset + 3]);
}
