#include "net/mac.hpp"

#include <stdio.h>

Mac mac_from_bytes(const uint8_t *data)
{
    Mac mac;

    for (int i = 0; i < MAC_LENGTH; i++)
        mac.bytes[i] = data[i];
    return mac;
}

std::string mac_to_string(Mac mac)
{
    char text[18];  // 6 fois "xx" + 5 fois ":" + le zero final

    snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac.bytes[0], mac.bytes[1], mac.bytes[2],
             mac.bytes[3], mac.bytes[4], mac.bytes[5]);
    return std::string(text);
}

bool mac_is_broadcast(Mac mac)
{
    for (int i = 0; i < MAC_LENGTH; i++) {
        if (mac.bytes[i] != 0xff)
            return false;
    }
    return true;
}

bool mac_is_multicast(Mac mac)
{
    return (mac.bytes[0] & 0x01) != 0;
}

bool operator==(const Mac &a, const Mac &b)
{
    for (int i = 0; i < MAC_LENGTH; i++) {
        if (a.bytes[i] != b.bytes[i])
            return false;
    }
    return true;
}
