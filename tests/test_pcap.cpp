#include "check.hpp"

#include <stdio.h>
#include <unistd.h>

#include "storage/pcap.hpp"

// Ecrit un fichier, le relit, et verifie qu'on retrouve exactement ce qu'on a
// mis dedans. C'est le test le plus important de ce module: si l'aller-retour
// est bon, le format est respecte.
static void test_round_trip(void)
{
    const char *path = "/tmp/mysniffer_test.pcap";
    const uint8_t first[4] = {0xde, 0xad, 0xbe, 0xef};
    const uint8_t second[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    PcapWriter writer;
    std::string error;

    CHECK(pcap_writer_open(&writer, path, &error) == true);
    CHECK(error.empty());

    CHECK(pcap_writer_write(&writer, first, sizeof(first), sizeof(first),
                            1700000000, 123456, &error) == true);
    // Un paquet tronque: on n'a garde que 8 octets sur 1500.
    CHECK(pcap_writer_write(&writer, second, sizeof(second), 1500,
                            1700000001, 654321, &error) == true);
    CHECK(writer.written == 2);
    pcap_writer_close(&writer);

    PcapReader reader;

    CHECK(pcap_reader_open(&reader, path, &error) == true);
    CHECK(reader.linktype == PCAP_LINKTYPE_ETHERNET);
    CHECK(reader.snaplen == 65535);
    CHECK(reader.swapped == false);
    CHECK(reader.nanoseconds == false);

    CapturedPacket packet;
    bool end = false;

    CHECK(pcap_reader_next(&reader, &packet, &end, &error) == true);
    CHECK(end == false);
    CHECK(packet.length == 4);
    CHECK(packet.original_length == 4);
    CHECK(packet.seconds == 1700000000);
    CHECK(packet.microseconds == 123456);
    CHECK(memcmp(packet.data, first, sizeof(first)) == 0);

    CHECK(pcap_reader_next(&reader, &packet, &end, &error) == true);
    CHECK(end == false);
    CHECK(packet.length == 8);
    // La taille reelle sur le cable doit avoir survecu a l'aller-retour.
    CHECK(packet.original_length == 1500);
    CHECK(packet.seconds == 1700000001);
    CHECK(memcmp(packet.data, second, sizeof(second)) == 0);

    // Troisieme lecture: c'est la fin du fichier, pas une erreur.
    CHECK(pcap_reader_next(&reader, &packet, &end, &error) == true);
    CHECK(end == true);

    pcap_reader_close(&reader);
    unlink(path);
}

// Verifie octet par octet que l'en-tete produit est conforme au format.
// Un fichier que nos propres fonctions relisent mais que Wireshark refuse
// serait inutile: on controle donc les octets eux-memes.
static void test_file_header_bytes(void)
{
    const char *path = "/tmp/mysniffer_header.pcap";
    PcapWriter writer;
    std::string error;

    CHECK(pcap_writer_open(&writer, path, &error) == true);
    pcap_writer_close(&writer);

    FILE *file = fopen(path, "rb");

    CHECK(file != NULL);
    if (file == NULL)
        return;

    uint8_t header[24];

    CHECK(fread(header, 1, sizeof(header), file) == sizeof(header));
    fclose(file);

    // Nombre magique 0xa1b2c3d4 ecrit en petit-boutiste.
    CHECK(header[0] == 0xd4);
    CHECK(header[1] == 0xc3);
    CHECK(header[2] == 0xb2);
    CHECK(header[3] == 0xa1);
    // Version 2.4.
    CHECK(header[4] == 2 && header[5] == 0);
    CHECK(header[6] == 4 && header[7] == 0);
    // Les deux champs inutilises sont a zero.
    for (int i = 8; i < 16; i++)
        CHECK(header[i] == 0);
    // Taille maximale 65535.
    CHECK(header[16] == 0xff && header[17] == 0xff);
    CHECK(header[18] == 0 && header[19] == 0);
    // Type de liaison 1, Ethernet.
    CHECK(header[20] == 1);
    CHECK(header[21] == 0 && header[22] == 0 && header[23] == 0);

    unlink(path);
}

// Un fichier ecrit sur une machine a l'ordre d'octets inverse doit se lire
// aussi. On en fabrique un a la main pour le verifier.
static void test_swapped_file(void)
{
    const char *path = "/tmp/mysniffer_swapped.pcap";
    FILE *file = fopen(path, "wb");

    CHECK(file != NULL);
    if (file == NULL)
        return;

    // Le meme en-tete, mais ecrit dans l'autre sens.
    const uint8_t header[24] = {
        0xa1, 0xb2, 0xc3, 0xd4,  // nombre magique a l'endroit
        0x00, 0x02, 0x00, 0x04,  // version 2.4
        0, 0, 0, 0,
        0, 0, 0, 0,
        0x00, 0x00, 0xff, 0xff,  // 65535
        0x00, 0x00, 0x00, 0x01,  // Ethernet
    };
    // Un paquet de 2 octets, date 1, en-tete lui aussi a l'envers.
    const uint8_t record[18] = {
        0, 0, 0, 1,
        0, 0, 0, 2,
        0, 0, 0, 2,
        0, 0, 0, 2,
        0xaa, 0xbb,
    };

    fwrite(header, 1, sizeof(header), file);
    fwrite(record, 1, sizeof(record), file);
    fclose(file);

    PcapReader reader;
    std::string error;

    CHECK(pcap_reader_open(&reader, path, &error) == true);
    CHECK(reader.swapped == true);
    CHECK(reader.snaplen == 65535);

    CapturedPacket packet;
    bool end = false;

    CHECK(pcap_reader_next(&reader, &packet, &end, &error) == true);
    CHECK(end == false);
    CHECK(packet.length == 2);
    CHECK(packet.seconds == 1);
    CHECK(packet.microseconds == 2);
    CHECK(packet.data[0] == 0xaa);
    CHECK(packet.data[1] == 0xbb);

    pcap_reader_close(&reader);
    unlink(path);
}

// Les fichiers abimes doivent etre refuses avec un message clair,
// jamais provoquer un plantage.
static void test_broken_files(void)
{
    const char *path = "/tmp/mysniffer_broken.pcap";
    PcapReader reader;
    std::string error;

    // Fichier qui n'existe pas.
    CHECK(pcap_reader_open(&reader, "/tmp/nexiste_vraiment_pas.pcap", &error) == false);
    CHECK(error.empty() == false);

    // Fichier vide.
    FILE *file = fopen(path, "wb");
    fclose(file);
    CHECK(pcap_reader_open(&reader, path, &error) == false);
    CHECK(error.find("trop court") != std::string::npos);

    // Fichier qui n'est pas du pcap du tout.
    file = fopen(path, "wb");
    fwrite("ceci n'est pas un pcap du tout!!", 1, 32, file);
    fclose(file);
    CHECK(pcap_reader_open(&reader, path, &error) == false);
    CHECK(error.find("pas un fichier pcap") != std::string::npos);

    // Un fichier pcapng doit etre reconnu comme tel, pour donner
    // un message utile plutot qu'un "format inconnu".
    file = fopen(path, "wb");
    const uint8_t pcapng[24] = {0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0,
                                0x4d, 0x3c, 0x2b, 0x1a, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0};
    fwrite(pcapng, 1, sizeof(pcapng), file);
    fclose(file);
    CHECK(pcap_reader_open(&reader, path, &error) == false);
    CHECK(error.find("pcapng") != std::string::npos);

    // En-tete correct, mais coupe au milieu d'un paquet.
    PcapWriter writer;
    CHECK(pcap_writer_open(&writer, path, &error) == true);
    const uint8_t data[4] = {1, 2, 3, 4};
    pcap_writer_write(&writer, data, sizeof(data), sizeof(data), 1, 2, &error);
    pcap_writer_close(&writer);

    // On tronque le fichier de deux octets.
    file = fopen(path, "rb");
    uint8_t whole[64];
    size_t size = fread(whole, 1, sizeof(whole), file);
    fclose(file);
    file = fopen(path, "wb");
    fwrite(whole, 1, size - 2, file);
    fclose(file);

    CHECK(pcap_reader_open(&reader, path, &error) == true);
    CapturedPacket packet;
    bool end = false;
    CHECK(pcap_reader_next(&reader, &packet, &end, &error) == false);
    CHECK(error.find("tronque") != std::string::npos);
    pcap_reader_close(&reader);

    unlink(path);
}

void test_pcap(void)
{
    printf("pcap\n");
    test_round_trip();
    test_file_header_bytes();
    test_swapped_file();
    test_broken_files();
}
