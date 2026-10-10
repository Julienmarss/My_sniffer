#include "check.hpp"

#include "net/mac.hpp"

void test_mac(void)
{
    printf("mac\n");

    const uint8_t raw[6] = {0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a};
    Mac mac = mac_from_bytes(raw);

    CHECK(mac_to_string(mac) == "c8:5e:a9:53:40:3a");
    CHECK(mac_is_broadcast(mac) == false);
    CHECK(mac_is_multicast(mac) == false);

    const uint8_t broadcast_raw[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    Mac broadcast = mac_from_bytes(broadcast_raw);

    CHECK(mac_to_string(broadcast) == "ff:ff:ff:ff:ff:ff");
    CHECK(mac_is_broadcast(broadcast) == true);
    // Le broadcast est un cas particulier de multicast: son premier octet
    // est 0xff, donc son bit de poids faible vaut 1.
    CHECK(mac_is_multicast(broadcast) == true);

    // Adresse multicast IPv4 classique: 01:00:5e:...
    const uint8_t multicast_raw[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01};
    Mac multicast = mac_from_bytes(multicast_raw);

    CHECK(mac_is_multicast(multicast) == true);
    CHECK(mac_is_broadcast(multicast) == false);

    // Les zeros en tete doivent apparaitre: on veut "00", pas "0".
    const uint8_t zero_raw[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};

    CHECK(mac_to_string(mac_from_bytes(zero_raw)) == "00:1a:2b:3c:4d:5e");
}
