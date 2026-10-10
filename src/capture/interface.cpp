#include "capture/interface.hpp"

#include <stddef.h>
#include <string.h>

// Windows n'a pas getifaddrs(): la liste des interfaces vient d'une API
// totalement differente (IP Helper). Le reste du fichier (find_or_add,
// interface_is_capturable) est commun; seul list_interfaces() a deux
// implementations completes, une par famille de systeme.
#if defined(_WIN32)
#  include <winsock2.h>
#  include <iphlpapi.h>
#  include <ws2tcpip.h>
#else
#  include <errno.h>
#  include <ifaddrs.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <sys/socket.h>

// L'adresse MAC est rangee dans une structure differente selon le systeme.
// C'est la SEULE difference entre Linux et la famille BSD dans ce fichier.
#  if defined(__linux__)
#    include <linux/if_packet.h>  // struct sockaddr_ll
#  else
#    include <net/if_dl.h>        // struct sockaddr_dl, sur FreeBSD et macOS
#  endif
#endif

#if !defined(_WIN32)

// Cherche l'interface qui porte ce nom et renvoie sa position dans la liste.
// Si elle n'y est pas encore, l'ajoute.
//
// C'est necessaire parce que getifaddrs() renvoie une entree par adresse et
// non par interface: la meme carte apparait plusieurs fois, une fois pour son
// adresse MAC, puis une fois par adresse IP qu'elle porte.
static size_t find_or_add(std::vector<Interface> &list,
                          const char *name, unsigned flags)
{
    for (size_t i = 0; i < list.size(); i++) {
        if (list[i].name == name)
            return i;
    }

    Interface iface;

    iface.name = name;
    iface.index = 0;
    iface.has_mac = false;
    iface.is_up = (flags & IFF_UP) != 0;
    iface.is_running = (flags & IFF_RUNNING) != 0;
    iface.is_loopback = (flags & IFF_LOOPBACK) != 0;
    list.push_back(iface);
    return list.size() - 1;
}

std::vector<Interface> list_interfaces(std::string *error)
{
    std::vector<Interface> result;
    struct ifaddrs *first = NULL;

    if (getifaddrs(&first) != 0) {
        if (error != NULL)
            *error = std::string("getifaddrs a echoue: ") + strerror(errno);
        return result;
    }

    for (struct ifaddrs *it = first; it != NULL; it = it->ifa_next) {
        if (it->ifa_name == NULL || it->ifa_addr == NULL)
            continue;

        size_t i = find_or_add(result, it->ifa_name, it->ifa_flags);
        int family = it->ifa_addr->sa_family;

        // reinterpret_cast: le systeme nous donne un pointeur generique
        // "struct sockaddr *". Le champ sa_family dit quelle est la vraie
        // structure derriere. On ne convertit qu'apres avoir verifie ce champ.

#if defined(__linux__)
        if (family == AF_PACKET) {
            const struct sockaddr_ll *ll =
                reinterpret_cast<const struct sockaddr_ll *>(it->ifa_addr);

            result[i].index = static_cast<unsigned>(ll->sll_ifindex);
            if (ll->sll_halen == MAC_LENGTH) {
                result[i].has_mac = true;
                result[i].mac = mac_from_bytes(ll->sll_addr);
            }
            continue;
        }
#else
        if (family == AF_LINK) {
            const struct sockaddr_dl *dl =
                reinterpret_cast<const struct sockaddr_dl *>(it->ifa_addr);

            result[i].index = dl->sdl_index;
            if (dl->sdl_alen == MAC_LENGTH) {
                // Dans cette structure, le nom de l'interface et l'adresse MAC
                // sont ranges l'un apres l'autre dans le meme tableau sdl_data.
                // L'adresse commence donc juste apres le nom.
                const uint8_t *data =
                    reinterpret_cast<const uint8_t *>(dl->sdl_data);

                result[i].has_mac = true;
                result[i].mac = mac_from_bytes(data + dl->sdl_nlen);
            }
            continue;
        }
#endif

        if (family == AF_INET) {
            const struct sockaddr_in *in =
                reinterpret_cast<const struct sockaddr_in *>(it->ifa_addr);
            InterfaceAddress address;

            address.ip = ipv4_from_bytes(
                reinterpret_cast<const uint8_t *>(&in->sin_addr));
            address.prefix_length = -1;

            if (it->ifa_netmask != NULL) {
                const struct sockaddr_in *mask =
                    reinterpret_cast<const struct sockaddr_in *>(it->ifa_netmask);

                address.prefix_length = ipv4_prefix_length(ipv4_from_bytes(
                    reinterpret_cast<const uint8_t *>(&mask->sin_addr)));
            }
            result[i].addresses.push_back(address);
        }
    }

    freeifaddrs(first);

    // Une interface sans entree de couche liaison n'a pas recu son numero.
    // On le demande alors au systeme a partir du nom.
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].index == 0)
            result[i].index = if_nametoindex(result[i].name.c_str());
    }

    return result;
}

#else  // _WIN32

// Sous Windows, la liste des interfaces vient de l'API IP Helper et non de
// getifaddrs(). GetAdaptersAddresses donne une entree par carte (pas par
// adresse), donc pas besoin d'un equivalent a find_or_add ici.
//
// Le nom garde par "name" est le GUID de l'adaptateur tel que Windows le
// donne (ex: "{4D36E972-...}"). C'est ce nom que capture_windows.cpp
// complete en "\Device\NPF_{...}" pour l'ouvrir avec Npcap: la conversion
// vit cote capture, pas ici, pour que ce fichier reste utilisable sans
// Npcap installe (afficher la liste ne demande aucun privilege).
std::vector<Interface> list_interfaces(std::string *error)
{
    std::vector<Interface> result;
    ULONG size = 0;
    ULONG flags = GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    // Premier appel pour connaitre la taille a allouer: personne ne connait
    // a l'avance le nombre de cartes ni d'adresses.
    GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size);

    std::vector<uint8_t> storage(size);
    IP_ADAPTER_ADDRESSES *first =
        reinterpret_cast<IP_ADAPTER_ADDRESSES *>(storage.data());
    ULONG status = GetAdaptersAddresses(AF_INET, flags, NULL, first, &size);

    if (status != NO_ERROR) {
        if (error != NULL)
            *error = "GetAdaptersAddresses a echoue (code " + std::to_string(status) + ")";
        return result;
    }

    for (IP_ADAPTER_ADDRESSES *adapter = first; adapter != NULL; adapter = adapter->Next) {
        Interface iface;

        iface.name = adapter->AdapterName;  // le GUID, pas le nom convivial
        iface.index = adapter->IfIndex;
        iface.is_up = (adapter->OperStatus == IfOperStatusUp);
        // Windows ne distingue pas "active" et "cable branche" au niveau de
        // cette API: on prend le meme etat pour les deux, en le disant.
        iface.is_running = iface.is_up;
        iface.is_loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

        iface.has_mac = false;
        if (adapter->PhysicalAddressLength == MAC_LENGTH) {
            iface.has_mac = true;
            iface.mac = mac_from_bytes(adapter->PhysicalAddress);
        }

        for (IP_ADAPTER_UNICAST_ADDRESS *addr = adapter->FirstUnicastAddress;
             addr != NULL; addr = addr->Next) {
            if (addr->Address.lpSockaddr->sa_family != AF_INET)
                continue;

            const sockaddr_in *in =
                reinterpret_cast<const sockaddr_in *>(addr->Address.lpSockaddr);
            InterfaceAddress address;

            address.ip = ipv4_from_bytes(
                reinterpret_cast<const uint8_t *>(&in->sin_addr));
            address.prefix_length = addr->OnLinkPrefixLength;
            iface.addresses.push_back(address);
        }

        result.push_back(iface);
    }

    return result;
}

#endif  // _WIN32

bool interface_is_capturable(const Interface &iface)
{
    return iface.is_up && !iface.is_loopback && iface.has_mac;
}
