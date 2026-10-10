#include "check.hpp"

#include "net/ipv4_address.hpp"

// Raccourci pour ecrire les tests lisiblement.
static Ipv4 ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    const uint8_t raw[4] = {a, b, c, d};

    return ipv4_from_bytes(raw);
}

void test_ipv4(void)
{
    printf("ipv4\n");

    CHECK(ipv4_to_string(ip(192, 168, 1, 10)) == "192.168.1.10");
    CHECK(ipv4_to_string(ip(0, 0, 0, 0)) == "0.0.0.0");
    CHECK(ipv4_to_string(ip(255, 255, 255, 255)) == "255.255.255.255");

    CHECK(ipv4_is_loopback(ip(127, 0, 0, 1)) == true);
    CHECK(ipv4_is_loopback(ip(128, 0, 0, 1)) == false);

    CHECK(ipv4_is_private(ip(10, 1, 2, 3)) == true);
    CHECK(ipv4_is_private(ip(192, 168, 1, 1)) == true);
    CHECK(ipv4_is_private(ip(8, 8, 8, 8)) == false);

    // Les bords de la plage 172.16.0.0/12, un piege classique:
    // elle va de 172.16 a 172.31, et pas jusqu'a 172.32.
    CHECK(ipv4_is_private(ip(172, 15, 255, 255)) == false);
    CHECK(ipv4_is_private(ip(172, 16, 0, 0)) == true);
    CHECK(ipv4_is_private(ip(172, 31, 255, 255)) == true);
    CHECK(ipv4_is_private(ip(172, 32, 0, 0)) == false);

    CHECK(ipv4_is_link_local(ip(169, 254, 1, 1)) == true);
    CHECK(ipv4_is_link_local(ip(169, 253, 1, 1)) == false);

    CHECK(ipv4_is_multicast(ip(224, 0, 0, 1)) == true);
    CHECK(ipv4_is_multicast(ip(239, 255, 255, 255)) == true);
    CHECK(ipv4_is_multicast(ip(240, 0, 0, 1)) == false);
    CHECK(ipv4_is_multicast(ip(223, 255, 255, 255)) == false);

    CHECK(ipv4_prefix_length(ip(255, 255, 255, 0)) == 24);
    CHECK(ipv4_prefix_length(ip(255, 255, 255, 255)) == 32);
    CHECK(ipv4_prefix_length(ip(0, 0, 0, 0)) == 0);
    CHECK(ipv4_prefix_length(ip(255, 240, 0, 0)) == 12);
    // Un masque troue n'est pas un prefixe valide.
    CHECK(ipv4_prefix_length(ip(255, 0, 255, 0)) == -1);
}
