// Capture sous FreeBSD et macOS, avec le peripherique bpf.
//
// Le principe est different de Linux: on ouvre un fichier special, on
// l'attache a une interface, et chaque lecture rend PLUSIEURS paquets d'un
// coup, colles les uns aux autres avec un petit en-tete devant chacun.
// Documente dans la page de manuel bpf(4).

#include "capture/capture.hpp"

#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void set_error(std::string *error, const std::string &what, int code)
{
    if (error == NULL)
        return;

    *error = what + ": " + strerror(code);
    if (code == EPERM || code == EACCES) {
        *error += "\nLire le trafic brut demande l'acces a /dev/bpf*.";
        *error += "\nEssayez avec sudo, ou voir docs/PRIVILEGES.md";
    }
}

// Ouvre un peripherique bpf libre.
//
// Sur FreeBSD, /dev/bpf se duplique tout seul a chaque ouverture: une seule
// tentative suffit. Sur macOS ce n'est pas le cas, il faut essayer /dev/bpf0,
// /dev/bpf1... jusqu'a en trouver un que personne n'utilise.
static int open_bpf_device(std::string *error)
{
    int fd = open("/dev/bpf", O_RDONLY);

    if (fd >= 0)
        return fd;

    // ENOENT veut dire que /dev/bpf n'existe pas: on est sur macOS.
    // Toute autre erreur (droits refuses, par exemple) est definitive.
    if (errno != ENOENT) {
        set_error(error, "impossible d'ouvrir /dev/bpf", errno);
        return -1;
    }

    // 256 est la limite habituelle du nombre de peripheriques bpf sur macOS
    // (sysctl debug.bpf_maxdevices). Au-dela, il n'y a plus rien a essayer.
    const int MAX_BPF_DEVICES = 256;

    for (int i = 0; i < MAX_BPF_DEVICES; i++) {
        char path[32];

        snprintf(path, sizeof(path), "/dev/bpf%d", i);
        fd = open(path, O_RDONLY);
        if (fd >= 0)
            return fd;
        // EBUSY: ce peripherique est pris par quelqu'un d'autre, on continue.
        if (errno != EBUSY) {
            set_error(error, std::string("impossible d'ouvrir ") + path, errno);
            return -1;
        }
    }

    if (error != NULL)
        *error = "tous les peripheriques /dev/bpf* sont occupes";
    return -1;
}

bool capture_open(Capture *capture, const std::string &interface_name,
                  bool promiscuous, std::string *error)
{
    capture->fd = -1;
    capture->buffer_used = 0;
    capture->buffer_position = 0;

    int fd = open_bpf_device(error);

    if (fd < 0)
        return false;

    // La taille du tampon doit etre choisie AVANT d'attacher l'interface.
    // Dans l'autre sens le systeme refuse. C'est ecrit dans bpf(4) et c'est
    // le genre de detail qui fait perdre une heure si on ne le lit pas.
    // 32 Kio: assez grand pour recevoir une bonne vingtaine de trames par
    // lecture, assez petit pour que le systeme l'accorde toujours. Le systeme
    // peut de toute facon nous en donner une autre, qu'on relit plus bas.
    unsigned int buffer_size = 32768;

    if (ioctl(fd, BIOCSBLEN, &buffer_size) < 0) {
        set_error(error, "impossible de regler la taille du tampon", errno);
        close(fd);
        return false;
    }

    // On attache le peripherique a l'interface voulue.
    struct ifreq request;

    memset(&request, 0, sizeof(request));
    strncpy(request.ifr_name, interface_name.c_str(), sizeof(request.ifr_name) - 1);

    if (ioctl(fd, BIOCSETIF, &request) < 0) {
        set_error(error, "impossible d'ecouter sur " + interface_name, errno);
        close(fd);
        return false;
    }

    // Mode immediat: rendre la main des qu'un paquet arrive. Sans lui, le
    // systeme attend que le tampon soit plein, ce qui donne un affichage
    // qui avance par a-coups au lieu de suivre le trafic.
    unsigned int enable = 1;

    if (ioctl(fd, BIOCIMMEDIATE, &enable) < 0) {
        set_error(error, "impossible d'activer le mode immediat", errno);
        close(fd);
        return false;
    }

    capture->promiscuous_active = false;
    if (promiscuous) {
        if (ioctl(fd, BIOCPROMISC, NULL) < 0) {
            // ENOTSUP/EOPNOTSUPP (meme valeur sur la plupart des systemes BSD)
            // veut dire que cette interface ne gere pas du tout le mode
            // espion, pas qu'on manque de droits. C'est le cas des
            // pseudo-interfaces internes de macOS (anpi0, awdl0...), actives
            // et montees mais pas destinees a du trafic ordinaire. On
            // continue alors sans mode espion plutot que de tout refuser.
            if (errno != ENOTSUP && errno != EOPNOTSUPP) {
                set_error(error, "impossible d'activer le mode espion", errno);
                close(fd);
                return false;
            }
        } else {
            capture->promiscuous_active = true;
        }
    }

    // On verifie qu'on est bien sur de l'Ethernet. Sur la boucle locale,
    // par exemple, l'en-tete est completement different et notre decodeur
    // Ethernet lirait n'importe quoi.
    unsigned int datalink = 0;

    if (ioctl(fd, BIOCGDLT, &datalink) < 0) {
        set_error(error, "impossible de connaitre le type de liaison", errno);
        close(fd);
        return false;
    }
    if (datalink != DLT_EN10MB) {
        if (error != NULL)
            *error = interface_name + " n'est pas une interface Ethernet";
        close(fd);
        return false;
    }

    // Le systeme peut avoir accorde une taille differente de celle demandee.
    // La lecture doit se faire avec un tampon d'exactement cette taille.
    if (ioctl(fd, BIOCGBLEN, &buffer_size) < 0) {
        set_error(error, "impossible de relire la taille du tampon", errno);
        close(fd);
        return false;
    }

    capture->fd = fd;
    capture->buffer.resize(buffer_size);
    return true;
}

bool capture_next(Capture *capture, CapturedPacket *packet, std::string *error)
{
    // Une lecture rend plusieurs paquets. On sert d'abord ceux qui restent
    // dans le tampon, et on ne relit le peripherique que quand ils sont tous
    // consommes. C'est la difference principale avec Linux, ou chaque appel
    // rend exactement un paquet.
    while (capture->buffer_position >= capture->buffer_used) {
        ssize_t received = read(capture->fd, capture->buffer.data(),
                                capture->buffer.size());

        if (received < 0) {
            // Meme regle que dans capture_linux.cpp: un signal n'est pas une
            // panne, on rend la main avec un message vide.
            if (errno == EINTR) {
                if (error != NULL)
                    error->clear();
                return false;
            }
            set_error(error, "erreur de lecture", errno);
            return false;
        }
        // Une lecture qui rend zero veut dire "rien a lire pour le moment":
        // le delai d'attente a expire sans qu'aucun paquet n'arrive. Ce n'est
        // pas une erreur, on redemande.
        //
        // Sans ce test explicite, la boucle repartirait quand meme, mais un
        // lecteur y verrait un tour a vide sans comprendre pourquoi. Pire, si
        // le peripherique rendait zero sans jamais bloquer, on tournerait a
        // plein regime sans le voir.
        if (received == 0)
            continue;

        capture->buffer_used = static_cast<size_t>(received);
        capture->buffer_position = 0;
    }

    // Il faut au moins de quoi contenir l'en-tete que bpf place devant
    // chaque paquet.
    if (capture->buffer_used - capture->buffer_position < sizeof(struct bpf_hdr)) {
        capture->buffer_position = capture->buffer_used;
        if (error != NULL)
            *error = "tampon bpf incoherent";
        return false;
    }

    const uint8_t *record = capture->buffer.data() + capture->buffer_position;
    struct bpf_hdr header;

    // On recopie l'en-tete au lieu de le lire sur place: rien ne garantit
    // qu'il tombe a une adresse correctement alignee dans le tampon.
    memcpy(&header, record, sizeof(header));

    size_t remaining = capture->buffer_used - capture->buffer_position;

    // Meme precaution que dans has_bytes: on ecrit le second test comme une
    // soustraction pour qu'une valeur enorme ne puisse pas deborder et faire
    // passer une lecture hors limites pour valide.
    if (header.bh_hdrlen > remaining
        || header.bh_caplen > remaining - header.bh_hdrlen) {
        capture->buffer_position = capture->buffer_used;
        if (error != NULL)
            *error = "paquet bpf incoherent";
        return false;
    }

    packet->data = record + header.bh_hdrlen;
    packet->length = header.bh_caplen;
    packet->original_length = header.bh_datalen;
    packet->seconds = header.bh_tstamp.tv_sec;
    packet->microseconds = header.bh_tstamp.tv_usec;

    // Chaque paquet commence a une position alignee. On utilise bh_hdrlen et
    // la macro du systeme, jamais sizeof() ni un nombre ecrit en dur:
    // l'en-tete et l'alignement ne font pas la meme taille sur FreeBSD et
    // sur macOS. C'est le piege classique de ce peripherique.
    capture->buffer_position += BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen);
    return true;
}

void capture_close(Capture *capture)
{
    if (capture->fd >= 0) {
        close(capture->fd);
        capture->fd = -1;
    }
    capture->buffer.clear();
    capture->buffer_used = 0;
    capture->buffer_position = 0;
}

unsigned long capture_dropped(Capture *capture)
{
    struct bpf_stat stats;

    memset(&stats, 0, sizeof(stats));
    if (ioctl(capture->fd, BIOCGSTATS, &stats) < 0)
        return 0;
    return stats.bs_drop;
}
