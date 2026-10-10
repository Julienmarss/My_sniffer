#include "check.hpp"

#include "net/bytes.hpp"

void test_bytes(void)
{
    printf("bytes\n");

    // Un debut de trame Ethernet: type 0x0800 (IPv4), puis 0xDEADBEEF.
    const uint8_t data[8] = {0x08, 0x00, 0x45, 0x00, 0xde, 0xad, 0xbe, 0xef};

    CHECK(read_u8(data, 0) == 0x08);
    CHECK(read_u16(data, 0) == 0x0800);
    CHECK(read_u16(data, 2) == 0x4500);
    CHECK(read_u32(data, 4) == 0xdeadbeef);

    // has_bytes accepte ce qui tient dans le tampon et refuse le reste.
    CHECK(has_bytes(8, 0, 8) == true);
    CHECK(has_bytes(8, 6, 2) == true);
    CHECK(has_bytes(8, 6, 3) == false);
    CHECK(has_bytes(8, 8, 0) == true);
    CHECK(has_bytes(8, 9, 0) == false);
    CHECK(has_bytes(0, 0, 1) == false);

    // Le cas qui compte vraiment: un offset enorme ne doit pas deborder
    // et faire croire que la lecture est possible. C'est exactement ce
    // qu'un paquet malveillant essaierait de provoquer.
    CHECK(has_bytes(8, (size_t)-1, 4) == false);
    CHECK(has_bytes(8, 4, (size_t)-1) == false);
}
