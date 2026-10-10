#include "storage/pcap.hpp"

#include <errno.h>
#include <string.h>

// Le nombre magique place au tout debut du fichier. Il sert a deux choses:
// dire "ceci est un fichier pcap", et reveler dans quel ordre d'octets il a
// ete ecrit. Si on le relit a l'envers, on trouve 0xd4c3b2a1 au lieu de
// 0xa1b2c3d4, et on sait qu'il faut retourner tous les nombres du fichier.
static const uint32_t PCAP_MAGIC = 0xa1b2c3d4;

// La meme chose, mais pour un fichier dont les dates sont en nanosecondes.
static const uint32_t PCAP_MAGIC_NANOSECONDS = 0xa1b23c4d;

// La version du format n'a pas bouge depuis les annees 1990.
static const uint16_t PCAP_VERSION_MAJOR = 2;
static const uint16_t PCAP_VERSION_MINOR = 4;

// Taille maximale qu'on accepte de lire pour un paquet. Un fichier abime
// pourrait annoncer une taille enorme; on refuse plutot que d'essayer
// d'allouer n'importe quoi.
static const uint32_t PCAP_MAX_PACKET = 262144;

// Taille maximale que nous annonçons capturer, ecrite dans l'en-tete du
// fichier. 65535 est la valeur habituelle: elle veut dire "on n'a rien coupe",
// puisque aucune trame Ethernet n'atteint cette taille.
static const uint32_t PCAP_SNAPLEN = 65535;

// Ecrit le message d'erreur, si l'appelant en veut un.
// Les fichiers de capture ont leur propre version, qui ajoute en plus la
// raison systeme et un conseil sur les privileges.
static void set_error(std::string *error, const std::string &message)
{
    if (error != NULL)
        *error = message;
}

// ----------------------------------------------------------------- ecriture

// On ecrit toujours dans l'ordre "petit-boutiste", octet de poids faible en
// premier. Ce n'est pas une obligation du format: le nombre magique dit au
// lecteur quel ordre a ete utilise. Mais en en choisissant un et en l'ecrivant
// nous-memes, le fichier produit est identique sur toutes les machines.
static void put_u16(uint8_t *out, uint16_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xff);
    out[1] = static_cast<uint8_t>(value >> 8);
}

static void put_u32(uint8_t *out, uint32_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xff);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xff);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xff);
}

bool pcap_writer_open(PcapWriter *writer, const std::string &path, std::string *error)
{
    writer->file = NULL;
    writer->written = 0;

    FILE *file = fopen(path.c_str(), "wb");

    if (file == NULL) {
        set_error(error, "impossible de creer " + path + ": " + strerror(errno));
        return false;
    }

    // L'en-tete de fichier fait 24 octets.
    uint8_t header[24];

    put_u32(header, PCAP_MAGIC);
    put_u16(header + 4, PCAP_VERSION_MAJOR);
    put_u16(header + 6, PCAP_VERSION_MINOR);
    put_u32(header + 8, 0);   // decalage horaire, jamais utilise: toujours zero
    put_u32(header + 12, 0);  // precision des dates, jamais utilise non plus
    put_u32(header + 16, PCAP_SNAPLEN);
    put_u32(header + 20, PCAP_LINKTYPE_ETHERNET);   // on ne produit que de l'Ethernet

    if (fwrite(header, 1, sizeof(header), file) != sizeof(header)) {
        set_error(error, "impossible d'ecrire l'en-tete de " + path);
        fclose(file);
        return false;
    }

    writer->file = file;
    return true;
}

bool pcap_writer_write(PcapWriter *writer, const uint8_t *data, size_t length,
                       size_t original_length, long seconds, long microseconds,
                       std::string *error)
{
    // L'en-tete de paquet fait 16 octets: la date en deux morceaux, la taille
    // capturee, puis la taille reelle sur le cable.
    uint8_t header[16];

    put_u32(header, static_cast<uint32_t>(seconds));
    put_u32(header + 4, static_cast<uint32_t>(microseconds));
    put_u32(header + 8, static_cast<uint32_t>(length));
    put_u32(header + 12, static_cast<uint32_t>(original_length));

    if (fwrite(header, 1, sizeof(header), writer->file) != sizeof(header)
        || fwrite(data, 1, length, writer->file) != length) {
        set_error(error, std::string("impossible d'ecrire le paquet: ") + strerror(errno));
        return false;
    }

    writer->written++;
    return true;
}

void pcap_writer_close(PcapWriter *writer)
{
    if (writer->file != NULL) {
        fclose(writer->file);
        writer->file = NULL;
    }
}

// ------------------------------------------------------------------ lecture

// Retourne les 4 octets sous forme de nombre, en tenant compte de l'ordre
// dans lequel le fichier a ete ecrit.
static uint32_t get_u32(const uint8_t *data, bool swapped)
{
    if (swapped) {
        return (static_cast<uint32_t>(data[0]) << 24)
             | (static_cast<uint32_t>(data[1]) << 16)
             | (static_cast<uint32_t>(data[2]) << 8)
             |  static_cast<uint32_t>(data[3]);
    }
    return (static_cast<uint32_t>(data[3]) << 24)
         | (static_cast<uint32_t>(data[2]) << 16)
         | (static_cast<uint32_t>(data[1]) << 8)
         |  static_cast<uint32_t>(data[0]);
}

static uint16_t get_u16(const uint8_t *data, bool swapped)
{
    if (swapped)
        return static_cast<uint16_t>((data[0] << 8) | data[1]);
    return static_cast<uint16_t>((data[1] << 8) | data[0]);
}

bool pcap_reader_open(PcapReader *reader, const std::string &path, std::string *error)
{
    reader->file = NULL;
    reader->swapped = false;
    reader->nanoseconds = false;

    FILE *file = fopen(path.c_str(), "rb");

    if (file == NULL) {
        set_error(error, "impossible d'ouvrir " + path + ": " + strerror(errno));
        return false;
    }

    uint8_t header[24];

    if (fread(header, 1, sizeof(header), file) != sizeof(header)) {
        set_error(error, path + " est trop court pour etre un fichier pcap");
        fclose(file);
        return false;
    }

    // On lit le nombre magique dans les deux sens et on regarde lequel donne
    // une valeur connue. C'est ce qui nous dit l'ordre d'octets du fichier
    // et l'unite des dates.
    uint32_t as_written = get_u32(header, false);
    uint32_t as_swapped = get_u32(header, true);

    if (as_written == PCAP_MAGIC) {
        reader->swapped = false;
        reader->nanoseconds = false;
    } else if (as_written == PCAP_MAGIC_NANOSECONDS) {
        reader->swapped = false;
        reader->nanoseconds = true;
    } else if (as_swapped == PCAP_MAGIC) {
        reader->swapped = true;
        reader->nanoseconds = false;
    } else if (as_swapped == PCAP_MAGIC_NANOSECONDS) {
        reader->swapped = true;
        reader->nanoseconds = true;
    } else {
        // 0x0a0d0d0a est le debut d'un fichier pcapng: on le reconnait pour
        // donner un message utile plutot qu'un "format inconnu".
        if (as_written == 0x0a0d0d0a || as_swapped == 0x0a0d0d0a)
            set_error(error, path + " est un fichier pcapng, format non gere");
        else
            set_error(error, path + " n'est pas un fichier pcap");
        fclose(file);
        return false;
    }

    uint16_t major = get_u16(header + 4, reader->swapped);

    if (major != PCAP_VERSION_MAJOR) {
        set_error(error, path + ": version de format inconnue (" + std::to_string(major) + ")");
        fclose(file);
        return false;
    }

    reader->snaplen = get_u32(header + 16, reader->swapped);
    reader->linktype = get_u32(header + 20, reader->swapped);

    // On ne sait decoder que de l'Ethernet. Sur un fichier capture sur la
    // boucle locale, par exemple, l'en-tete est different et notre decodeur
    // lirait n'importe quoi. Mieux vaut le dire clairement.
    if (reader->linktype != PCAP_LINKTYPE_ETHERNET) {
        set_error(error, path + ": type de liaison " + std::to_string(reader->linktype)
                   + " non gere, seul Ethernet (1) l'est");
        fclose(file);
        return false;
    }

    reader->file = file;
    reader->buffer.resize(PCAP_MAX_PACKET);
    return true;
}

bool pcap_reader_next(PcapReader *reader, CapturedPacket *packet,
                      bool *end, std::string *error)
{
    *end = false;

    uint8_t header[16];
    size_t read_bytes = fread(header, 1, sizeof(header), reader->file);

    if (read_bytes == 0) {
        *end = true;  // fin normale du fichier
        return true;
    }
    if (read_bytes != sizeof(header)) {
        set_error(error, "fichier tronque au milieu d'un en-tete de paquet");
        return false;
    }

    uint32_t seconds = get_u32(header, reader->swapped);
    uint32_t fraction = get_u32(header + 4, reader->swapped);
    uint32_t length = get_u32(header + 8, reader->swapped);
    uint32_t original_length = get_u32(header + 12, reader->swapped);

    // La taille vient du fichier, donc on ne lui fait pas confiance.
    if (length > PCAP_MAX_PACKET) {
        set_error(error, "paquet de taille aberrante (" + std::to_string(length) + " octets)");
        return false;
    }

    if (fread(reader->buffer.data(), 1, length, reader->file) != length) {
        set_error(error, "fichier tronque au milieu d'un paquet");
        return false;
    }

    packet->data = reader->buffer.data();
    packet->length = length;
    packet->original_length = original_length;
    packet->seconds = static_cast<long>(seconds);
    // On ramene toujours a des microsecondes, pour que le reste du programme
    // n'ait pas a savoir dans quelle unite le fichier etait ecrit.
    packet->microseconds = reader->nanoseconds
                         ? static_cast<long>(fraction / 1000)
                         : static_cast<long>(fraction);
    return true;
}

void pcap_reader_close(PcapReader *reader)
{
    if (reader->file != NULL) {
        fclose(reader->file);
        reader->file = NULL;
    }
    reader->buffer.clear();
}
