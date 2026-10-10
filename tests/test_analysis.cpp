#include "check.hpp"

#include "analysis/analysis.hpp"
#include "dissect/decode.hpp"

#include <string.h>

// Fabrique une trame Ethernet + IPv4 + TCP complete, pour nourrir l'analyse.
// On n'a pas besoin de sommes de controle justes ici: l'analyse ne les regarde
// pas, elle ne s'interesse qu'aux adresses, aux ports et aux drapeaux.
static std::vector<uint8_t> make_tcp_frame(const char *source, const char *destination,
                                           uint16_t source_port, uint16_t destination_port,
                                           uint8_t flags, const char *payload)
{
    size_t payload_size = (payload != NULL) ? strlen(payload) : 0;
    std::vector<uint8_t> frame(14 + 20 + 20 + payload_size, 0);
    Ipv4 from;
    Ipv4 to;

    // Pas de CHECK ici: cette fonction est appelee des centaines de fois par
    // les boucles de test, et cela gonflerait le compte de verifications sans
    // rien prouver. Une adresse mal ecrite ferait de toute facon echouer le
    // test qui l'utilise.
    ipv4_from_string(source, &from);
    ipv4_from_string(destination, &to);

    frame[12] = 0x08;                                   // type Ethernet: IPv4
    frame[14] = 0x45;                                   // version 4, en-tete de 20 octets

    uint16_t total = static_cast<uint16_t>(20 + 20 + payload_size);

    frame[16] = static_cast<uint8_t>(total >> 8);
    frame[17] = static_cast<uint8_t>(total & 0xff);
    frame[22] = 64;                                     // TTL
    frame[23] = 6;                                      // protocole: TCP
    for (int i = 0; i < 4; i++) {
        frame[26 + i] = from.bytes[i];
        frame[30 + i] = to.bytes[i];
    }

    frame[34] = static_cast<uint8_t>(source_port >> 8);
    frame[35] = static_cast<uint8_t>(source_port & 0xff);
    frame[36] = static_cast<uint8_t>(destination_port >> 8);
    frame[37] = static_cast<uint8_t>(destination_port & 0xff);
    frame[46] = 0x50;                                   // en-tete TCP de 20 octets
    frame[47] = flags;

    for (size_t i = 0; i < payload_size; i++)
        frame[54 + i] = static_cast<uint8_t>(payload[i]);

    return frame;
}

// Donne une trame a l'analyse.
static void feed(Analysis *analysis, const std::vector<uint8_t> &frame, long seconds)
{
    DecodedPacket decoded = decode_packet(frame.data(), frame.size());

    analysis_add(analysis, decoded, frame.data(), frame.size(), seconds);
}

// Vrai si une alerte de ce type a ete levee.
static bool has_alert(const std::vector<Alert> &alerts, const char *kind)
{
    for (size_t i = 0; i < alerts.size(); i++) {
        if (alerts[i].kind == kind)
            return true;
    }
    return false;
}

// Une capture ordinaire ne doit produire aucune alerte: un detecteur qui
// crie tout le temps ne sert a rien, on apprend a l'ignorer.
static void test_quiet_traffic(void)
{
    Analysis analysis = analysis_start(default_analysis_settings());

    for (int i = 0; i < 20; i++) {
        feed(&analysis, make_tcp_frame("192.168.1.10", "192.168.1.20",
                                       40000 + static_cast<uint16_t>(i), 445, 0x10, NULL),
             1700000000 + i);
    }

    std::vector<Alert> alerts = analysis_report(analysis);

    CHECK(alerts.empty() == true);
}

// 1. Beaucoup de requetes vers un meme service.
//
// Ce qui compte est le DEBIT, pas le nombre total. Les deux cas ci-dessous
// envoient exactement le meme nombre de paquets au meme service: seule la
// duree change, et c'est elle qui fait la difference entre un balayage et
// une consultation ordinaire.
static void test_too_many_requests(void)
{
    AnalysisSettings settings = default_analysis_settings();

    settings.max_requests = 50;

    // 300 paquets en une seconde: un balayage.
    Analysis burst = analysis_start(settings);

    for (int i = 0; i < 300; i++) {
        feed(&burst, make_tcp_frame("192.168.1.10", "192.168.1.50",
                                    40000 + static_cast<uint16_t>(i), 3306, 0x02, NULL),
             1700000000);
    }
    CHECK(has_alert(analysis_report(burst), "requetes") == true);

    // Les memes 300 paquets etales sur dix minutes: une page web.
    Analysis spread = analysis_start(settings);

    for (int i = 0; i < 300; i++) {
        feed(&spread, make_tcp_frame("192.168.1.10", "192.168.1.50",
                                     40000 + static_cast<uint16_t>(i), 443, 0x18, NULL),
             1700000000 + i * 2);
    }
    CHECK(has_alert(analysis_report(spread), "requetes") == false);

    // Et le seuil de debit doit repondre quand on le change.
    settings.max_requests_per_second = 1000;

    Analysis tolerant = analysis_start(settings);

    for (int i = 0; i < 300; i++) {
        feed(&tolerant, make_tcp_frame("192.168.1.10", "192.168.1.50",
                                       40000 + static_cast<uint16_t>(i), 3306, 0x02, NULL),
             1700000000);
    }
    CHECK(has_alert(analysis_report(tolerant), "requetes") == false);
}

// Un reseau declare connu ne doit plus rien declencher: ni comme destination
// exterieure, ni comme balise. C'est ce qui permet de parler de connexion
// "non autorisee" et non d'un simple inventaire de tout ce qui sort.
static void test_allowed_networks(void)
{
    std::vector<uint8_t> frame = make_tcp_frame("192.168.1.10", "203.0.113.77",
                                                51000, 8443, 0x18, "x");

    // Sans liste blanche: l'adresse est signalee, et sa regularite aussi.
    Analysis strict = analysis_start(default_analysis_settings());

    for (int i = 0; i < 10; i++)
        feed(&strict, frame, 1700000000 + i * 30);

    std::vector<Alert> alerts = analysis_report(strict);

    CHECK(has_alert(alerts, "exterieur") == true);
    CHECK(has_alert(alerts, "balise") == true);

    // Avec le reseau declare connu: plus rien.
    AnalysisSettings settings = default_analysis_settings();
    AllowedNetwork network;

    CHECK(ipv4_from_string("203.0.113.0", &network.address) == true);
    network.prefix_length = 24;
    settings.allowed.push_back(network);

    CHECK(analysis_is_allowed(settings, network.address) == true);

    Analysis relaxed = analysis_start(settings);

    for (int i = 0; i < 10; i++)
        feed(&relaxed, frame, 1700000000 + i * 30);

    alerts = analysis_report(relaxed);
    CHECK(has_alert(alerts, "exterieur") == false);
    CHECK(has_alert(alerts, "balise") == false);

    // Un reseau voisin mais different ne doit pas etre couvert par erreur.
    AnalysisSettings other = default_analysis_settings();
    AllowedNetwork elsewhere;

    CHECK(ipv4_from_string("198.51.100.0", &elsewhere.address) == true);
    elsewhere.prefix_length = 24;
    other.allowed.push_back(elsewhere);

    CHECK(analysis_is_allowed(other, network.address) == false);
}

// 2. Beaucoup de refus en retour.
static void test_too_many_errors(void)
{
    AnalysisSettings settings = default_analysis_settings();

    settings.max_errors = 5;

    Analysis analysis = analysis_start(settings);

    // Drapeaux RST + ACK: le serveur refuse la connexion.
    for (int i = 0; i < 10; i++) {
        feed(&analysis, make_tcp_frame("192.168.1.60", "192.168.1.10",
                                       22, 50000 + static_cast<uint16_t>(i), 0x14, NULL),
             1700000000);
    }

    CHECK(has_alert(analysis_report(analysis), "erreurs") == true);
}

// 3. Pic de trafic.
static void test_traffic_spike(void)
{
    Analysis analysis = analysis_start(default_analysis_settings());
    std::vector<uint8_t> frame = make_tcp_frame("192.168.1.10", "192.168.1.20",
                                                40000, 445, 0x10, NULL);

    // Dix secondes calmes, puis une seconde tres chargee.
    for (int second = 0; second < 10; second++) {
        for (int i = 0; i < 2; i++)
            feed(&analysis, frame, 1700000000 + second);
    }
    for (int i = 0; i < 200; i++)
        feed(&analysis, frame, 1700000010);

    CHECK(has_alert(analysis_report(analysis), "pic") == true);
}

// 4. Connexions vers l'exterieur.
static void test_outside_destinations(void)
{
    Analysis analysis = analysis_start(default_analysis_settings());

    feed(&analysis, make_tcp_frame("192.168.1.10", "8.8.8.8", 40000, 53, 0x10, NULL),
         1700000000);

    CHECK(has_alert(analysis_report(analysis), "exterieur") == true);

    // Une adresse de diffusion ou privee ne doit pas compter comme exterieure.
    Analysis local = analysis_start(default_analysis_settings());

    feed(&local, make_tcp_frame("192.168.1.10", "255.255.255.255", 68, 67, 0x10, NULL),
         1700000000);
    feed(&local, make_tcp_frame("192.168.1.10", "10.0.0.1", 40000, 80, 0x10, NULL),
         1700000000);

    CHECK(has_alert(analysis_report(local), "exterieur") == false);
}

// 5. Protocole inattendu sur un port standard.
static void test_unexpected_protocol(void)
{
    Analysis analysis = analysis_start(default_analysis_settings());

    // Du HTTP sur le port 80: rien a signaler.
    feed(&analysis, make_tcp_frame("192.168.1.10", "93.184.216.34", 40000, 80, 0x18,
                                   "GET / HTTP/1.1\r\n"), 1700000000);
    CHECK(has_alert(analysis_report(analysis), "port") == false);

    // Autre chose sur le port 80: on le signale.
    Analysis odd = analysis_start(default_analysis_settings());

    feed(&odd, make_tcp_frame("192.168.1.10", "93.184.216.34", 40000, 80, 0x18,
                              "CECI N EST PAS DU HTTP"), 1700000000);
    CHECK(has_alert(analysis_report(odd), "port") == true);

    // Du TLS sur le port 443: normal. L'octet 0x16 est une poignee de main,
    // le 0x03 la version majeure, inchangee depuis SSL 3.0.
    Analysis tls = analysis_start(default_analysis_settings());

    // Les chaines sont separees volontairement: colle, "\x01ABCD" serait lu
    // comme un seul code hexadecimal et non comme un octet suivi de lettres.
    feed(&tls, make_tcp_frame("192.168.1.10", "93.184.216.34", 40000, 443, 0x18,
                              "\x16\x03\x01" "ABCD"), 1700000000);
    CHECK(has_alert(analysis_report(tls), "port") == false);
}

// 6. Appels a intervalle regulier vers l'exterieur.
static void test_beaconing(void)
{
    Analysis analysis = analysis_start(default_analysis_settings());
    std::vector<uint8_t> frame = make_tcp_frame("192.168.1.10", "203.0.113.77",
                                                51000, 8443, 0x18, "x");

    // Toutes les 30 secondes, dix fois: le rythme d'une machine, pas d'un humain.
    for (int i = 0; i < 10; i++)
        feed(&analysis, frame, 1700000000 + i * 30);

    CHECK(has_alert(analysis_report(analysis), "balise") == true);

    // Une connexion active envoie un paquet par seconde. C'est regulier, mais
    // ce n'est pas une balise: c'est une page en train de charger. Sans ce
    // filtre, chaque onglet ouvert dans un navigateur declenchait une alerte.
    Analysis busy = analysis_start(default_analysis_settings());
    std::vector<uint8_t> active = make_tcp_frame("192.168.1.10", "203.0.113.77",
                                                 51000, 443, 0x18, "x");

    for (int i = 0; i < 15; i++)
        feed(&busy, active, 1700000000 + i);

    CHECK(has_alert(analysis_report(busy), "balise") == false);

    // Des intervalles irreguliers ne doivent rien declencher.
    Analysis irregular = analysis_start(default_analysis_settings());
    const long moments[] = {0, 3, 40, 41, 95, 96, 200, 201, 400};

    for (size_t i = 0; i < sizeof(moments) / sizeof(moments[0]); i++)
        feed(&irregular, frame, 1700000000 + moments[i]);

    CHECK(has_alert(analysis_report(irregular), "balise") == false);

    // Une regularite vers une machine du reseau local est la norme, pas une
    // anomalie: une machine interroge son serveur DNS a heure fixe.
    Analysis inside = analysis_start(default_analysis_settings());
    std::vector<uint8_t> local = make_tcp_frame("192.168.1.10", "192.168.1.1",
                                                51000, 53, 0x18, "x");

    for (int i = 0; i < 10; i++)
        feed(&inside, local, 1700000000 + i * 30);

    CHECK(has_alert(analysis_report(inside), "balise") == false);
}

// L'analyse recoit des paquets venus du reseau: elle ne doit jamais planter,
// meme sur des trames coupees n'importe ou.
static void test_truncated_packets(void)
{
    Analysis analysis = analysis_start(default_analysis_settings());
    std::vector<uint8_t> frame = make_tcp_frame("192.168.1.10", "8.8.8.8", 40000, 80,
                                                0x18, "GET / HTTP/1.1\r\n");

    for (size_t cut = 0; cut <= frame.size(); cut++) {
        DecodedPacket decoded = decode_packet(frame.data(), cut);

        analysis_add(&analysis, decoded, frame.data(), cut, 1700000000);
    }

    // On ne verifie rien de precis: ce qui compte est d'arriver jusqu'ici,
    // et que les detecteurs de bugs memoire n'aient rien trouve.
    CHECK(analysis.total_packets == static_cast<long>(frame.size()) + 1);
    analysis_report(analysis);
}

void test_analysis(void)
{
    printf("analysis\n");
    test_quiet_traffic();
    test_too_many_requests();
    test_allowed_networks();
    test_too_many_errors();
    test_traffic_spike();
    test_outside_destinations();
    test_unexpected_protocol();
    test_beaconing();
    test_truncated_packets();
}
