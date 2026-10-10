// Collecte: on remplit les compteurs, on ne juge rien ici.
// Le verdict est rendu dans report.cpp.

#include "analysis/analysis.hpp"

#include <string.h>

#include "dissect/ipv4.hpp"

AnalysisSettings default_analysis_settings(void)
{
    AnalysisSettings settings;

    // Ces valeurs conviennent a quelques minutes de capture sur un poste de
    // travail ordinaire. Elles sont volontairement genereuses: mieux vaut
    // rater une anomalie discrete que noyer l'utilisateur sous les fausses
    // alertes, qui lui apprendraient a ne plus les lire.
    settings.max_requests = 200;
    settings.max_requests_per_second = 50;
    settings.max_errors = 20;
    settings.spike_factor = 5;
    settings.min_beacon_samples = 5;
    settings.min_beacon_interval = 10;
    settings.beacon_tolerance = 15;
    return settings;
}

bool analysis_is_allowed(const AnalysisSettings &settings, Ipv4 address)
{
    for (size_t i = 0; i < settings.allowed.size(); i++) {
        if (ipv4_in_network(address, settings.allowed[i].address,
                            settings.allowed[i].prefix_length))
            return true;
    }
    return false;
}

// Les cles doivent pouvoir etre rangees dans une map, d'ou ces comparaisons.
// On compare l'adresse comme un nombre, puis le port en cas d'egalite.
bool operator<(const ServiceKey &a, const ServiceKey &b)
{
    uint32_t left = ipv4_to_uint(a.address);
    uint32_t right = ipv4_to_uint(b.address);

    if (left != right)
        return left < right;
    return a.port < b.port;
}

bool operator<(const ConversationKey &a, const ConversationKey &b)
{
    uint32_t left = ipv4_to_uint(a.source);
    uint32_t right = ipv4_to_uint(b.source);

    if (left != right)
        return left < right;

    left = ipv4_to_uint(a.destination);
    right = ipv4_to_uint(b.destination);
    if (left != right)
        return left < right;

    return a.port < b.port;
}

Analysis analysis_start(const AnalysisSettings &settings)
{
    Analysis analysis;

    analysis.settings = settings;
    analysis.total_packets = 0;
    analysis.first_seconds = 0;
    analysis.last_seconds = 0;
    return analysis;
}

// ------------------------------------------------ protocole sur un port

// Ce qu'on s'attend a trouver au debut des donnees, selon le port.
//
// On ne cherche pas a decoder le protocole, seulement a reconnaitre sa
// signature de depart. Si elle manque sur un port standard, c'est peut-etre
// un programme qui se cache derriere un numero de port rassurant.
struct PortSignature {
    uint16_t port;
    const char *expected;   // nom lisible du protocole attendu
};

// Vrai si les donnees ressemblent a du HTTP: une methode connue, ou une
// reponse. Les methodes sont definies par la RFC 9110.
static bool looks_like_http(const uint8_t *payload, size_t size)
{
    static const char *starts[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
                                   "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
                                   "HTTP/1."};

    for (size_t i = 0; i < sizeof(starts) / sizeof(starts[0]); i++) {
        size_t length = strlen(starts[i]);

        if (size >= length && memcmp(payload, starts[i], length) == 0)
            return true;
    }
    return false;
}

// Vrai si les donnees ressemblent a du TLS. Un enregistrement TLS commence par
// son type (20 a 23), puis la version majeure, qui vaut 3 depuis SSL 3.0.
static bool looks_like_tls(const uint8_t *payload, size_t size)
{
    if (size < 3)
        return false;
    return payload[0] >= 20 && payload[0] <= 23 && payload[1] == 0x03;
}

// Vrai si les donnees ressemblent a du SSH: la banniere commence par "SSH-".
static bool looks_like_ssh(const uint8_t *payload, size_t size)
{
    return size >= 4 && memcmp(payload, "SSH-", 4) == 0;
}

// Regarde si le contenu correspond au port utilise.
static void check_port_usage(Analysis *analysis, const DecodedPacket &packet,
                             const uint8_t *data, size_t size)
{
    if (!packet.has_tcp || packet.tcp.payload_length == 0)
        return;
    if (packet.tcp.payload_offset >= size)
        return;

    const uint8_t *payload = data + packet.tcp.payload_offset;
    size_t available = size - packet.tcp.payload_offset;
    uint16_t port = packet.tcp.destination_port;
    const char *expected = NULL;
    bool matches = false;

    if (port == 80 || port == 8080) {
        expected = "HTTP";
        matches = looks_like_http(payload, available);
    } else if (port == 443) {
        expected = "TLS";
        matches = looks_like_tls(payload, available);
    } else if (port == 22) {
        expected = "SSH";
        matches = looks_like_ssh(payload, available);
    }

    if (expected == NULL || matches)
        return;

    // Une seule alerte par service suffit: sinon un transfert entier en
    // produirait des milliers.
    std::string message = "le port " + std::to_string(port) + " de "
                        + ipv4_to_string(packet.ipv4.destination)
                        + " ne transporte pas du " + expected
                        + " comme on s'y attendrait";

    for (size_t i = 0; i < analysis->port_alerts.size(); i++) {
        if (analysis->port_alerts[i].message == message)
            return;
    }

    Alert alert;

    alert.kind = "port";
    alert.message = message;
    analysis->port_alerts.push_back(alert);
}

// ---------------------------------------------------------------- collecte

void analysis_add(Analysis *analysis, const DecodedPacket &packet,
                  const uint8_t *data, size_t size, long seconds)
{
    if (analysis->total_packets == 0)
        analysis->first_seconds = seconds;
    analysis->total_packets++;
    analysis->last_seconds = seconds;
    analysis->packets_per_second[seconds]++;

    if (!packet.has_ipv4)
        return;

    // Une adresse publique en destination veut dire que la machine parle a
    // l'exterieur du reseau local. C'est normal pour du web, ca l'est moins
    // pour un programme qu'on n'attendait pas.
    if (ipv4_is_public(packet.ipv4.destination))
        analysis->outside_destinations[packet.ipv4.destination]++;

    uint16_t source_port = 0;
    uint16_t destination_port = 0;

    if (packet.has_tcp) {
        source_port = packet.tcp.source_port;
        destination_port = packet.tcp.destination_port;
    } else if (packet.has_udp) {
        source_port = packet.udp.source_port;
        destination_port = packet.udp.destination_port;
    } else {
        return;   // ni TCP ni UDP: pas de notion de service
    }

    // Le service vise recoit une requete de plus.
    ServiceKey target;

    target.address = packet.ipv4.destination;
    target.port = destination_port;

    ServiceCounters &counters = analysis->services[target];

    if (counters.requests == 0)
        counters.first_seconds = seconds;
    counters.requests++;
    counters.last_seconds = seconds;

    // Un RST veut dire "je refuse". On le compte pour le service qui l'emet,
    // c'est-a-dire l'expediteur de ce paquet.
    if (packet.has_tcp && packet.tcp.rst) {
        ServiceKey refuser;

        refuser.address = packet.ipv4.source;
        refuser.port = source_port;
        analysis->services[refuser].errors++;
    }

    // Les ecarts entre paquets d'une meme conversation, pour reperer un
    // programme qui appelle a intervalle fixe.
    ConversationKey conversation;

    conversation.source = packet.ipv4.source;
    conversation.destination = packet.ipv4.destination;
    conversation.port = destination_port;

    ConversationCounters &talk = analysis->conversations[conversation];

    if (talk.packets > 0) {
        long gap = seconds - talk.last_seconds;

        // On ignore les paquets de la meme seconde: ils font partie du meme
        // echange, pas d'un rythme. Et on borne le nombre d'ecarts gardes,
        // pour que la memoire ne grandisse pas indefiniment.
        if (gap > 0 && talk.gaps.size() < 200)
            talk.gaps.push_back(gap);
    }
    talk.packets++;
    talk.last_seconds = seconds;

    check_port_usage(analysis, packet, data, size);
}
