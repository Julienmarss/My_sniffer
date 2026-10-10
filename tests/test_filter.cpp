#include "check.hpp"

#include "dissect/decode.hpp"
#include "filter/filter.hpp"

// On reutilise les trames du fichier de test du decodage.
extern const uint8_t *filter_test_tcp_frame(size_t *size);
extern const uint8_t *filter_test_udp_frame(size_t *size);

// Raccourci: la regle garde-t-elle ce paquet ?
static bool keeps(const char *rule, const uint8_t *data, size_t size)
{
    Filter filter;
    std::string error;

    if (!filter_parse(rule, &filter, &error)) {
        printf("  regle refusee alors qu'elle devrait passer: %s (%s)\n", rule, error.c_str());
        return false;
    }
    return filter_matches(filter, decode_packet(data, size));
}

// Une regle mal ecrite doit etre refusee, avec un message.
static void check_rejected(const char *rule)
{
    Filter filter;
    std::string error;

    CHECK(filter_parse(rule, &filter, &error) == false);
    CHECK(error.empty() == false);
    // Meme refusee, la regle doit rester utilisable sans planter.
    CHECK(filter_is_empty(filter) == true);
}

void test_filter(void)
{
    printf("filter\n");

    size_t tcp_size = 0;
    size_t udp_size = 0;
    const uint8_t *tcp = filter_test_tcp_frame(&tcp_size);
    const uint8_t *udp = filter_test_udp_frame(&udp_size);

    // La trame TCP: 192.168.1.10:54321 vers 93.184.216.34:80, drapeau SYN.
    // La trame UDP: 192.168.1.10:51000 vers 8.8.8.8:53.

    // --- une regle vide laisse tout passer ---
    Filter empty;
    std::string error;

    CHECK(filter_parse("", &empty, &error) == true);
    CHECK(filter_is_empty(empty) == true);
    CHECK(filter_matches(empty, decode_packet(tcp, tcp_size)) == true);

    // --- protocoles ---
    CHECK(keeps("tcp", tcp, tcp_size) == true);
    CHECK(keeps("udp", tcp, tcp_size) == false);
    CHECK(keeps("udp", udp, udp_size) == true);
    CHECK(keeps("tcp", udp, udp_size) == false);
    CHECK(keeps("ip", tcp, tcp_size) == true);
    CHECK(keeps("arp", tcp, tcp_size) == false);
    CHECK(keeps("eth", tcp, tcp_size) == true);

    // --- adresses ---
    CHECK(keeps("host 192.168.1.10", tcp, tcp_size) == true);
    CHECK(keeps("host 93.184.216.34", tcp, tcp_size) == true);
    CHECK(keeps("host 1.2.3.4", tcp, tcp_size) == false);
    // Avec une direction, un seul cote compte.
    CHECK(keeps("src host 192.168.1.10", tcp, tcp_size) == true);
    CHECK(keeps("dst host 192.168.1.10", tcp, tcp_size) == false);
    CHECK(keeps("dst host 93.184.216.34", tcp, tcp_size) == true);

    // --- reseaux ---
    CHECK(keeps("net 192.168.0.0/16", tcp, tcp_size) == true);
    CHECK(keeps("net 192.168.1.0/24", tcp, tcp_size) == true);
    CHECK(keeps("net 10.0.0.0/8", tcp, tcp_size) == false);
    CHECK(keeps("src net 192.168.1.10/32", tcp, tcp_size) == true);
    // Un prefixe de 0 bit designe tout Internet.
    CHECK(keeps("net 0.0.0.0/0", tcp, tcp_size) == true);

    // --- ports ---
    CHECK(keeps("port 80", tcp, tcp_size) == true);
    CHECK(keeps("port 54321", tcp, tcp_size) == true);
    CHECK(keeps("port 22", tcp, tcp_size) == false);
    CHECK(keeps("dst port 80", tcp, tcp_size) == true);
    CHECK(keeps("src port 80", tcp, tcp_size) == false);
    CHECK(keeps("dst port 53", udp, udp_size) == true);
    CHECK(keeps("portrange 79-81", tcp, tcp_size) == true);
    CHECK(keeps("portrange 100-200", tcp, tcp_size) == false);

    // --- drapeaux TCP ---
    CHECK(keeps("tcp-flags syn", tcp, tcp_size) == true);
    CHECK(keeps("tcp-flags ack", tcp, tcp_size) == false);
    // Demander plusieurs drapeaux exige qu'ils soient TOUS presents.
    CHECK(keeps("tcp-flags syn,ack", tcp, tcp_size) == false);
    // Un paquet UDP n'a pas de drapeaux TCP.
    CHECK(keeps("tcp-flags syn", udp, udp_size) == false);

    // --- longueur de la trame ---
    CHECK(keeps("len > 10", tcp, tcp_size) == true);
    CHECK(keeps("len < 10", tcp, tcp_size) == false);
    CHECK(keeps("len >= 54", tcp, tcp_size) == true);
    CHECK(keeps("len = 54", tcp, tcp_size) == true);
    CHECK(keeps("len != 54", tcp, tcp_size) == false);

    // --- combinaisons ---
    CHECK(keeps("tcp and dst port 80", tcp, tcp_size) == true);
    CHECK(keeps("tcp and dst port 22", tcp, tcp_size) == false);
    CHECK(keeps("udp or tcp", tcp, tcp_size) == true);
    CHECK(keeps("not tcp", tcp, tcp_size) == false);
    CHECK(keeps("not udp", tcp, tcp_size) == true);
    CHECK(keeps("tcp and not port 22", tcp, tcp_size) == true);

    // "and" se lie plus fort que "or": la regle ci-dessous se lit
    // "udp or (tcp and port 80)", elle garde donc la trame TCP.
    CHECK(keeps("udp or tcp and port 80", tcp, tcp_size) == true);
    // Les parentheses permettent de changer ce regroupement.
    CHECK(keeps("(udp or tcp) and port 9999", tcp, tcp_size) == false);
    CHECK(keeps("(udp or tcp) and port 80", tcp, tcp_size) == true);

    // Les formes courtes des operateurs.
    CHECK(keeps("tcp && port 80", tcp, tcp_size) == true);
    CHECK(keeps("udp || tcp", tcp, tcp_size) == true);
    CHECK(keeps("! udp", tcp, tcp_size) == true);

    // --- regles mal ecrites: refusees avec un message, jamais un plantage ---
    check_rejected("nimportequoi");
    check_rejected("tcp and");
    check_rejected("and tcp");
    check_rejected("host");
    check_rejected("host pas.une.adresse");
    check_rejected("host 999.1.1.1");
    check_rejected("port");
    check_rejected("port abc");
    check_rejected("port 70000");
    check_rejected("net 192.168.1.0/33");
    check_rejected("net 192.168.1.0/");
    check_rejected("tcp-flags nawak");
    check_rejected("len");
    check_rejected("len ~ 100");
    check_rejected("len > abc");
    check_rejected("(tcp");
    check_rejected("tcp)");
    check_rejected("tcp 80");
    check_rejected("portrange 100");
    check_rejected("portrange 200-100");
    check_rejected("src tcp");

    // Ces regles-la etaient acceptees en silence avant correction, parce que
    // atoi() rend zero pour un texte qui n'est pas un nombre. "net X/abc"
    // devenait "net X/0" et gardait tout le trafic sans prevenir: une faute
    // de frappe dans un filtre passait donc inapercue.
    check_rejected("net 192.168.1.0/abc");
    check_rejected("net 192.168.1.0/999");
    check_rejected("portrange abc-def");
    check_rejected("portrange -100");
    check_rejected("portrange 80-abc");
    check_rejected("port -1");

    // Et les regles voisines, elles, doivent continuer a passer.
    CHECK(keeps("net 0.0.0.0/0", tcp, tcp_size) == true);
    CHECK(keeps("net 192.168.1.0/24", tcp, tcp_size) == true);
    CHECK(keeps("portrange 80-443", tcp, tcp_size) == true);
    CHECK(keeps("port 0", tcp, tcp_size) == false);

    // Une regle trop imbriquee doit etre refusee, PAS faire planter le
    // programme. Sans cette limite, une regle de 50000 parentheses epuisait
    // la pile et provoquait une erreur de segmentation, ce que le sujet
    // sanctionne lourdement.
    //
    // Trois formes provoquaient le plantage, chacune pour une raison
    // differente, d'ou les trois tests.
    std::string deep_parentheses;

    for (int i = 0; i < 500; i++)
        deep_parentheses += "(";
    deep_parentheses += "tcp";
    for (int i = 0; i < 500; i++)
        deep_parentheses += ")";
    check_rejected(deep_parentheses.c_str());

    std::string many_not;

    for (int i = 0; i < 500; i++)
        many_not += "not ";
    many_not += "tcp";
    check_rejected(many_not.c_str());

    // Celle-ci s'analysait sans probleme: c'est l'EVALUATION qui plantait,
    // au premier paquet, parce que l'arbre etait aussi profond qu'il y avait
    // de conditions. Le plantage arrivait donc bien apres la lecture de la
    // regle, ce qui le rendait difficile a rattacher a sa cause.
    std::string many_and = "tcp";

    for (int i = 0; i < 500; i++)
        many_and += " and tcp";
    check_rejected(many_and.c_str());

    // Et les regles d'imbrication raisonnable doivent continuer a passer.
    CHECK(keeps("((((tcp))))", tcp, tcp_size) == true);
    CHECK(keeps("not not tcp", tcp, tcp_size) == true);
    CHECK(keeps("tcp and tcp and tcp and tcp and tcp", tcp, tcp_size) == true);
}
