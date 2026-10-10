#include "dissect/tcp.hpp"

#include "net/bytes.hpp"
#include "net/checksum.hpp"

bool parse_tcp(const uint8_t *data, size_t size, size_t offset,
               size_t segment_length, Ipv4 source_ip, Ipv4 destination_ip,
               TcpHeader *out)
{
    // L'en-tete TCP fait au minimum 20 octets.
    if (!has_bytes(size, offset, 20))
        return false;

    out->source_port = read_u16(data, offset);
    out->destination_port = read_u16(data, offset + 2);
    out->sequence = read_u32(data, offset + 4);
    out->acknowledgment = read_u32(data, offset + 8);

    // L'octet 12 porte deux choses: la taille de l'en-tete dans ses 4 bits de
    // poids fort, et le drapeau AE dans son bit de poids faible.
    uint8_t length_and_ae = read_u8(data, offset + 12);

    // Taille comptee en mots de 4 octets. Le minimum legal est 5, soit 20 octets.
    size_t words = length_and_ae >> 4;

    if (words < 5)
        return false;
    out->header_length = words * 4;

    // L'en-tete peut aller jusqu'a 60 octets s'il porte des options
    // (taille maximale de segment, horodatage...). On verifie qu'on les a.
    if (!has_bytes(size, offset, out->header_length))
        return false;

    out->ae = (length_and_ae & 0x01) != 0;

    uint8_t flags = read_u8(data, offset + 13);

    out->cwr = (flags & 0x80) != 0;
    out->ece = (flags & 0x40) != 0;
    out->urg = (flags & 0x20) != 0;
    out->ack = (flags & 0x10) != 0;
    out->psh = (flags & 0x08) != 0;
    out->rst = (flags & 0x04) != 0;
    out->syn = (flags & 0x02) != 0;
    out->fin = (flags & 0x01) != 0;

    out->window = read_u16(data, offset + 14);

    out->payload_offset = offset + out->header_length;
    out->payload_length = 0;
    if (segment_length > out->header_length)
        out->payload_length = segment_length - out->header_length;

    // On ne garde que ce qu'on a vraiment recu.
    size_t available = size - out->payload_offset;

    if (out->payload_length > available)
        out->payload_length = available;

    // La somme de controle couvre le pseudo en-tete, l'en-tete TCP et les
    // donnees.
    //
    // ATTENTION: cette fonction ne sait pas si la capture a coupe le segment,
    // parce qu'elle recoit deja une longueur ramenee a ce qui est disponible.
    // Le resultat n'a donc de sens que si le segment est complet. C'est a
    // l'appelant de le savoir et de ne pas afficher "somme invalide" sinon.
    // Voir summary.cpp, qui dispose de l'information.
    out->checksum_valid = false;
    if (has_bytes(size, offset, segment_length)) {
        uint32_t sum = pseudo_header_sum(source_ip, destination_ip, 6,
                                         static_cast<uint16_t>(segment_length));

        sum += checksum_add(data + offset, segment_length);
        out->checksum_valid = checksum_finish(sum) == 0;
    }

    return true;
}

// Ajoute un drapeau a la liste s'il est actif, avec la virgule qui va bien.
// Sans cette fonction, le nom de chaque drapeau serait ecrit deux fois par
// ligne, neuf fois de suite.
static void add_flag(std::string *text, bool active, const char *name)
{
    if (!active)
        return;
    if (!text->empty())
        *text += ", ";
    *text += name;
}

std::string tcp_flags_string(const TcpHeader &header)
{
    std::string text;

    // On garde l'ordre des schemas de la RFC, du bit de poids fort au faible.
    add_flag(&text, header.ae, "AE");
    add_flag(&text, header.cwr, "CWR");
    add_flag(&text, header.ece, "ECE");
    add_flag(&text, header.urg, "URG");
    add_flag(&text, header.ack, "ACK");
    add_flag(&text, header.psh, "PSH");
    add_flag(&text, header.rst, "RST");
    add_flag(&text, header.syn, "SYN");
    add_flag(&text, header.fin, "FIN");

    if (text.empty())
        return "aucun";
    return text;
}
