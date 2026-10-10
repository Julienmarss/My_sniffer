// Capture sous Linux, avec une socket AF_PACKET.
//
// Le principe: on ouvre une socket qui recoit les trames brutes, en-tete
// Ethernet compris, on l'attache a une seule interface, puis on lit paquet
// par paquet. Documente dans la page de manuel packet(7).

#include "capture/capture.hpp"

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// Le noyau attend le numero de protocole en ordre reseau, c'est-a-dire
// l'octet de poids fort en premier. La fonction habituelle pour ca, htons(),
// vient de <arpa/inet.h>, un en-tete reseau que le sujet nous interdit.
// On fabrique donc la valeur nous-memes, ce qui marche sur toute machine.
static uint16_t to_network_order(uint16_t value)
{
    uint16_t result = 0;
    uint8_t *bytes = reinterpret_cast<uint8_t *>(&result);

    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value & 0xff);
    return result;
}

// Message d'erreur systeme, avec un conseil quand c'est un probleme de droits.
static void set_error(std::string *error, const std::string &what, int code)
{
    if (error == NULL)
        return;

    *error = what + ": " + strerror(code);
    if (code == EPERM || code == EACCES) {
        *error += "\nLire le trafic brut demande des privileges. Essayez avec sudo,";
        *error += "\nou donnez la capacite au programme: voir docs/PRIVILEGES.md";
    }
}

bool capture_open(Capture *capture, const std::string &interface_name,
                  bool promiscuous, std::string *error)
{
    capture->fd = -1;
    capture->buffer_used = 0;
    capture->buffer_position = 0;

    // ETH_P_ALL veut dire "tous les protocoles": on veut tout voir passer.
    // SOCK_RAW veut dire "avec l'en-tete Ethernet", par opposition a
    // SOCK_DGRAM qui nous le retirerait.
    int fd = socket(AF_PACKET, SOCK_RAW, to_network_order(ETH_P_ALL));

    if (fd < 0) {
        set_error(error, "impossible d'ouvrir la socket de capture", errno);
        return false;
    }

    // Le noyau designe les interfaces par un numero, pas par leur nom.
    unsigned index = if_nametoindex(interface_name.c_str());

    if (index == 0) {
        set_error(error, "interface introuvable: " + interface_name, errno);
        close(fd);
        return false;
    }

    // Sans cette etape, on recevrait le trafic de TOUTES les interfaces,
    // avec des en-tetes de formats differents selon leur type.
    struct sockaddr_ll address;

    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = to_network_order(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(index);

    if (bind(fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) < 0) {
        set_error(error, "impossible d'ecouter sur " + interface_name, errno);
        close(fd);
        return false;
    }

    // Le mode espion fait accepter a la carte reseau les trames qui ne lui
    // sont pas destinees. Sans lui, on ne voit que notre propre trafic.
    //
    // On le demande en adherant a un groupe plutot qu'en modifiant l'interface.
    // Deux avantages: ca demande un privilege plus faible, et surtout le noyau
    // annule l'adhesion tout seul si le programme s'arrete. En modifiant
    // l'interface, elle resterait en mode espion apres un plantage.
    if (promiscuous) {
        struct packet_mreq request;

        memset(&request, 0, sizeof(request));
        request.mr_ifindex = static_cast<int>(index);
        request.mr_type = PACKET_MR_PROMISC;

        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                       &request, sizeof(request)) < 0) {
            set_error(error, "impossible d'activer le mode espion", errno);
            close(fd);
            return false;
        }
    }

    capture->fd = fd;
    capture->promiscuous_active = promiscuous;
    // 65536 octets, soit plus que la plus grande trame Ethernet possible.
    capture->buffer.resize(65536);
    return true;
}

bool capture_next(Capture *capture, CapturedPacket *packet, std::string *error)
{
    // MSG_TRUNC change le comportement de recv: il fait renvoyer la taille
    // REELLE du paquet, meme si notre tampon etait trop petit pour tout
    // prendre. On sait donc quand un paquet a ete tronque, au lieu de croire
    // qu'il etait court.
    ssize_t received = recv(capture->fd, capture->buffer.data(),
                            capture->buffer.size(), MSG_TRUNC);

    if (received < 0) {
        // Un signal a interrompu la lecture, un Ctrl+C par exemple.
        // Ce n'est pas une panne: on rend la main avec un message vide, et
        // c'est a l'appelant de decider s'il s'arrete ou s'il reessaie.
        if (errno == EINTR) {
            if (error != NULL)
                error->clear();
            return false;
        }
        set_error(error, "erreur de lecture", errno);
        return false;
    }

    packet->original_length = static_cast<size_t>(received);
    packet->length = packet->original_length;
    if (packet->length > capture->buffer.size())
        packet->length = capture->buffer.size();
    packet->data = capture->buffer.data();

    // On date le paquet a sa reception. Le noyau sait donner une date plus
    // precise, prise au moment exact ou la carte a recu la trame, mais il
    // faut passer par recvmsg et lire des messages annexes. Ce sera une
    // amelioration possible; ici l'ecart est de quelques microsecondes.
    struct timeval now;

    gettimeofday(&now, NULL);
    packet->seconds = now.tv_sec;
    packet->microseconds = now.tv_usec;
    return true;
}

void capture_close(Capture *capture)
{
    if (capture->fd >= 0) {
        close(capture->fd);
        capture->fd = -1;
    }
    capture->buffer.clear();
}

unsigned long capture_dropped(Capture *capture)
{
    struct tpacket_stats stats;
    socklen_t size = sizeof(stats);

    memset(&stats, 0, sizeof(stats));
    if (getsockopt(capture->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &size) < 0)
        return 0;
    return stats.tp_drops;
}
