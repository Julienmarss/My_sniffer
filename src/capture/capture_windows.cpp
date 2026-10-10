// Capture sous Windows, avec Npcap.
//
// Winsock2 seul ne donne jamais l'en-tete Ethernet sous Windows (contrairement
// a AF_PACKET sous Linux ou bpf sous BSD): c'est une limite du systeme, pas un
// choix. Npcap est la seule facon d'obtenir la trame brute sans ecrire un
// pilote reseau nous-memes, ce que le sujet ne demande pas. C'est pourquoi
// cette version, et seulement celle-ci, s'appuie sur une bibliotheque: le
// reste (Ethernet, IPv4, TCP, UDP, filtre, analyse) reste notre code partout,
// y compris ici. Voir docs/PRIVILEGES.md pour l'installation de Npcap.
//
// Npcap n'utilise qu'un paquet a la fois par appel, comme AF_PACKET: cette
// version suit donc le modele de capture_linux.cpp, pas celui de
// capture_bsd.cpp qui doit decouper plusieurs paquets d'un meme tampon.

#include "capture/capture.hpp"

#include <pcap.h>
#include <windows.h>

#include <string.h>

// Npcap attend le nom interne du peripherique, pas le GUID que
// list_interfaces() affiche. La conversion est documentee par Npcap lui-meme:
// "\Device\NPF_" suivi du GUID de l'adaptateur.
static std::string npcap_device_name(const std::string &interface_name)
{
    return "\\Device\\NPF_" + interface_name;
}

// Ctrl+C sous Windows n'interrompt pas un appel bloquant comme le ferait un
// signal POSIX: pcap_next_ex doit etre rappelee regulierement pour qu'on ait
// une chance de constater l'arret demande. On installe donc notre propre
// gestionnaire, uniquement pour positionner ce drapeau; il rend FALSE pour
// laisser la chaine de gestionnaires continuer (le programme a aussi le
// sien, installe par commands.cpp, qui affiche le bilan).
static volatile LONG interrupted = 0;

static BOOL WINAPI on_console_event(DWORD event_type)
{
    if (event_type == CTRL_C_EVENT || event_type == CTRL_BREAK_EVENT)
        InterlockedExchange(&interrupted, 1);
    return FALSE;
}

static void ensure_handler_installed(void)
{
    static bool installed = false;

    if (!installed) {
        SetConsoleCtrlHandler(on_console_event, TRUE);
        installed = true;
    }
}

// Message d'erreur avec un conseil quand Npcap n'est pas installe ou que les
// droits manquent.
static void set_error(std::string *error, const std::string &what, const std::string &detail)
{
    if (error == NULL)
        return;

    *error = what + ": " + detail;
    *error += "\nVerifiez que Npcap est installe (avec l acces WinPcap active),";
    *error += "\net que le programme tourne en administrateur: voir docs/PRIVILEGES.md";
}

bool capture_open(Capture *capture, const std::string &interface_name,
                  bool promiscuous, std::string *error)
{
    capture->fd = -1;
    capture->handle = NULL;
    capture->buffer_used = 0;
    capture->buffer_position = 0;

    ensure_handler_installed();

    char errbuf[PCAP_ERRBUF_SIZE];
    std::string device = npcap_device_name(interface_name);

    // 65536: plus que la plus grande trame Ethernet possible, comme sur les
    // autres systemes. 1000 ms: le temps qu'on accepte d'attendre avant de
    // reprendre la main pour verifier si un Ctrl+C est arrive.
    pcap_t *handle = pcap_open_live(device.c_str(), 65536,
                                    promiscuous ? 1 : 0, 1000, errbuf);

    if (handle == NULL) {
        set_error(error, "impossible d'ouvrir la capture sur " + interface_name, errbuf);
        return false;
    }

    capture->handle = handle;
    // Npcap ne distingue pas "refuse" de "non gere": pcap_open_live echouerait
    // dans les deux cas plutot que de rendre la main sans mode espion. On ne
    // peut donc que constater ce qui a ete demande, pas le verifier a part.
    capture->promiscuous_active = promiscuous;
    return true;
}

bool capture_next(Capture *capture, CapturedPacket *packet, std::string *error)
{
    pcap_t *handle = reinterpret_cast<pcap_t *>(capture->handle);

    for (;;) {
        if (InterlockedCompareExchange(&interrupted, 0, 0)) {
            if (error != NULL)
                error->clear();
            return false;
        }

        struct pcap_pkthdr *header;
        const unsigned char *data;
        int status = pcap_next_ex(handle, &header, &data);

        if (status == 1) {
            packet->data = data;
            packet->length = header->caplen;
            packet->original_length = header->len;
            packet->seconds = static_cast<long>(header->ts.tv_sec);
            packet->microseconds = static_cast<long>(header->ts.tv_usec);
            return true;
        }

        if (status == 0)
            continue;  // rien recu pendant le delai d'attente, ce n'est pas une panne

        set_error(error, "erreur de lecture", pcap_geterr(handle));
        return false;
    }
}

void capture_close(Capture *capture)
{
    if (capture->handle != NULL) {
        pcap_close(reinterpret_cast<pcap_t *>(capture->handle));
        capture->handle = NULL;
    }
    capture->fd = -1;
    capture->buffer.clear();
}

unsigned long capture_dropped(Capture *capture)
{
    struct pcap_stat stats;

    memset(&stats, 0, sizeof(stats));
    if (pcap_stats(reinterpret_cast<pcap_t *>(capture->handle), &stats) != 0)
        return 0;
    return stats.ps_drop;
}
