// Point d'entree du programme.
//
// Ce fichier ne fait qu'une chose: lire la ligne de commande et appeler la
// bonne fonction. Tout le travail est dans cli/commands.cpp.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "analysis/analysis.hpp"
#include "cli/commands.hpp"
#include "log/log.hpp"
#include "term/color.hpp"

static void print_usage(void)
{
    printf("Usage: mysniffer <commande> [options]\n");
    printf("\n");
    printf("Commandes:\n");
    printf("  interfaces        liste les cartes reseau utilisables\n");
    printf("  capture           affiche les paquets qui passent\n");
    printf("  read              relit un fichier .pcap deja enregistre\n");
    printf("  analyze           cherche les comportements anormaux\n");
    printf("\n");
    printf("Options de la commande interfaces:\n");
    printf("  -a, --all         montre aussi les interfaces inutilisables\n");
    printf("\n");
    printf("Options de la commande capture:\n");
    printf("  -i, --interface X sur quelle interface ecouter\n");
    printf("  -c, --count N     s'arreter apres N paquets\n");
    printf("  -p, --no-promisc  ne pas activer le mode espion\n");
    printf("  -w, --write F     enregistrer dans F au lieu d'afficher\n");
    printf("  -f, --filter R    ne garder que les paquets qui suivent la regle R\n");
    printf("\n");
    printf("Options de la commande read:\n");
    printf("  -r, --read F      le fichier .pcap a relire\n");
    printf("  -c, --count N     s'arreter apres N paquets\n");
    printf("  -f, --filter R    ne garder que les paquets qui suivent la regle R\n");
    printf("\n");
    printf("Options de la commande analyze:\n");
    printf("  -r, --read F      analyser un fichier .pcap\n");
    printf("  -i, --interface X analyser le trafic en direct\n");
    printf("  -c, --count N     s'arreter apres N paquets\n");
    printf("  -f, --filter R    n'analyser que les paquets suivant la regle R\n");
    printf("      --allow N/P   declarer un reseau connu (repetable), ex: 8.8.8.0/24\n");
    printf("      --max-requests N    nombre de paquets avant de s'interesser a un service\n");
    printf("      --max-rate N        paquets par seconde au-dela desquels on signale\n");
    printf("      --max-errors N      refus de connexion avant de signaler un service\n");
    printf("      --spike-factor N    une seconde est un pic au-dela de N fois la moyenne\n");
    printf("      --beacon-interval N intervalle minimal, en secondes, d'une balise\n");
    printf("\n");
    printf("Regles de filtrage, quelques exemples:\n");
    printf("  tcp                                    les paquets TCP\n");
    printf("  port 443                               tout ce qui touche au port 443\n");
    printf("  dst port 53                            les requetes vers un serveur DNS\n");
    printf("  host 8.8.8.8                           tout ce qui parle a cette machine\n");
    printf("  net 192.168.0.0/16                     tout un reseau\n");
    printf("  tcp and dst port 80                    les deux a la fois\n");
    printf("  tcp-flags syn and not tcp-flags ack    les debuts de connexion\n");
    printf("  udp or icmp                            l'un ou l'autre\n");
    printf("  len > 1000                             les gros paquets\n");
    printf("\n");
    printf("Mots reconnus: eth arp vlan ip ip6 icmp tcp udp,\n");
    printf("               src dst host net port portrange tcp-flags len,\n");
    printf("               and or not, et les parentheses.\n");
    printf("\n");
    printf("Options generales:\n");
    printf("  -v, --verbose     journal plus bavard (repetable: -vv)\n");
    printf("      --log-level L niveau du journal: debug, info, warn, error\n");
    printf("      --log-file F  ecrire le journal dans F au lieu de la sortie d'erreur\n");
    printf("      --color M     couleur de l'affichage: auto, always, never\n");
    printf("  -V, --version     affiche la version\n");
    printf("  -h, --help        affiche cette aide\n");
    printf("\n");
    printf("Le journal raconte la vie du programme (interface ouverte, paquets\n");
    printf("perdus, arret). Il est separe du resultat, qui va sur la sortie\n");
    printf("standard: 'mysniffer read -r x.pcap > sortie.txt' ne melange pas les deux.\n");
    printf("\n");
    printf("Par defaut la couleur n'apparait que si la sortie est un terminal:\n");
    printf("rediriger vers un fichier donne du texte brut, sans codes parasites.\n");
    printf("\n");
    printf("La capture demande des privileges: lancez-la avec sudo.\n");
}

// Vrai si l'argument est cette option, sous sa forme courte ou longue.
static bool is_option(const char *argument, const char *short_form, const char *long_form)
{
    return strcmp(argument, short_form) == 0 || strcmp(argument, long_form) == 0;
}

// Recupere la valeur qui suit une option, en avancant l'indice.
// Retourne false et se plaint si la valeur manque, par exemple "capture -i"
// tout seul en fin de ligne.
static bool take_value(int argc, char **argv, int *i, std::string *value)
{
    if (*i + 1 >= argc) {
        fprintf(stderr, "erreur: l'option '%s' attend une valeur\n", argv[*i]);
        return false;
    }
    *value = argv[++(*i)];
    return true;
}

// Lit un nombre ecrit en chiffres, et rien d'autre.
// On n'utilise pas atoi: elle rend zero aussi bien pour "0" que pour "abc",
// donc une faute de frappe passerait pour un reglage valide.
static bool parse_decimal(const std::string &text, long maximum, long *out)
{
    if (text.empty())
        return false;

    long value = 0;

    for (size_t i = 0; i < text.size(); i++) {
        if (text[i] < '0' || text[i] > '9')
            return false;
        value = value * 10 + (text[i] - '0');
        if (value > maximum)
            return false;
    }
    *out = value;
    return true;
}

// Lit un nombre de paquets. Refuse ce qui n'est pas un nombre, plutot que de
// prendre zero en silence et de tout capturer.
static bool take_count(int argc, char **argv, int *i, long *count)
{
    std::string text;

    if (!take_value(argc, argv, i, &text))
        return false;

    char *end = NULL;

    *count = strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0' || *count < 0) {
        fprintf(stderr, "erreur: '%s' n'est pas un nombre de paquets valide\n",
                text.c_str());
        return false;
    }
    return true;
}

static int run_interfaces(int argc, char **argv)
{
    bool show_all = false;

    for (int i = 2; i < argc; i++) {
        if (is_option(argv[i], "-a", "--all")) {
            show_all = true;
        } else if (is_option(argv[i], "-h", "--help")) {
            print_usage();
            return 0;
        } else {
            fprintf(stderr, "erreur: option inconnue '%s'\n", argv[i]);
            return 1;
        }
    }
    return command_interfaces(show_all);
}

static int run_capture(int argc, char **argv)
{
    CaptureOptions options;

    options.count = 0;
    options.promiscuous = true;

    for (int i = 2; i < argc; i++) {
        if (is_option(argv[i], "-i", "--interface")) {
            if (!take_value(argc, argv, &i, &options.interface_name))
                return 1;
        } else if (is_option(argv[i], "-w", "--write")) {
            if (!take_value(argc, argv, &i, &options.output_path))
                return 1;
        } else if (is_option(argv[i], "-c", "--count")) {
            if (!take_count(argc, argv, &i, &options.count))
                return 1;
        } else if (is_option(argv[i], "-f", "--filter")) {
            if (!take_value(argc, argv, &i, &options.filter))
                return 1;
        } else if (is_option(argv[i], "-p", "--no-promisc")) {
            options.promiscuous = false;
        } else if (is_option(argv[i], "-h", "--help")) {
            print_usage();
            return 0;
        } else {
            fprintf(stderr, "erreur: option inconnue '%s'\n", argv[i]);
            return 1;
        }
    }
    return command_capture(options);
}

static int run_read(int argc, char **argv)
{
    ReadOptions options;

    options.count = 0;

    for (int i = 2; i < argc; i++) {
        if (is_option(argv[i], "-r", "--read")) {
            if (!take_value(argc, argv, &i, &options.path))
                return 1;
        } else if (is_option(argv[i], "-c", "--count")) {
            if (!take_count(argc, argv, &i, &options.count))
                return 1;
        } else if (is_option(argv[i], "-f", "--filter")) {
            if (!take_value(argc, argv, &i, &options.filter))
                return 1;
        } else if (is_option(argv[i], "-h", "--help")) {
            print_usage();
            return 0;
        } else if (argv[i][0] != '-' && options.path.empty()) {
            // On accepte aussi "mysniffer read fichier.pcap", plus court.
            options.path = argv[i];
        } else {
            fprintf(stderr, "erreur: option inconnue '%s'\n", argv[i]);
            return 1;
        }
    }
    return command_read(options);
}

static int run_analyze(int argc, char **argv)
{
    AnalyzeOptions options;

    options.count = 0;
    options.settings = default_analysis_settings();

    for (int i = 2; i < argc; i++) {
        // Les reglages de l'analyse. On les traite ensemble, ils se ressemblent.
        long *number = NULL;

        if (strcmp(argv[i], "--max-requests") == 0)
            number = &options.settings.max_requests;
        else if (strcmp(argv[i], "--max-rate") == 0)
            number = &options.settings.max_requests_per_second;
        else if (strcmp(argv[i], "--max-errors") == 0)
            number = &options.settings.max_errors;
        else if (strcmp(argv[i], "--spike-factor") == 0)
            number = &options.settings.spike_factor;
        else if (strcmp(argv[i], "--beacon-interval") == 0)
            number = &options.settings.min_beacon_interval;

        if (number != NULL) {
            if (!take_count(argc, argv, &i, number))
                return 1;
            continue;
        }

        if (strcmp(argv[i], "--allow") == 0) {
            std::string text;

            if (!take_value(argc, argv, &i, &text))
                return 1;

            AllowedNetwork network;
            size_t slash = text.find('/');
            std::string address_part = (slash == std::string::npos)
                                     ? text : text.substr(0, slash);

            if (!ipv4_from_string(address_part, &network.address)) {
                fprintf(stderr, "erreur: '%s' n'est pas un reseau valide,"
                                " attendu par exemple 8.8.8.0/24\n", text.c_str());
                return 1;
            }

            // Sans "/N", on prend /32: une seule machine.
            network.prefix_length = 32;
            if (slash != std::string::npos) {
                long bits = 0;

                if (!parse_decimal(text.substr(slash + 1), 32, &bits)) {
                    fprintf(stderr, "erreur: apres le '/', on attend un nombre"
                                    " de bits de 0 a 32\n");
                    return 1;
                }
                network.prefix_length = static_cast<int>(bits);
            }

            options.settings.allowed.push_back(network);
            continue;
        }

        if (is_option(argv[i], "-r", "--read")) {
            if (!take_value(argc, argv, &i, &options.path))
                return 1;
        } else if (is_option(argv[i], "-i", "--interface")) {
            if (!take_value(argc, argv, &i, &options.interface_name))
                return 1;
        } else if (is_option(argv[i], "-f", "--filter")) {
            if (!take_value(argc, argv, &i, &options.filter))
                return 1;
        } else if (is_option(argv[i], "-c", "--count")) {
            if (!take_count(argc, argv, &i, &options.count))
                return 1;
        } else if (is_option(argv[i], "-h", "--help")) {
            print_usage();
            return 0;
        } else if (argv[i][0] != '-' && options.path.empty()) {
            options.path = argv[i];
        } else {
            fprintf(stderr, "erreur: option inconnue '%s'\n", argv[i]);
            return 1;
        }
    }
    return command_analyze(options);
}

// Retire de la ligne de commande les options valables pour toutes les
// commandes, avant tout le reste, pour que le journal et la couleur soient
// deja en place quand la commande demarre.
//
// Retourne false si une de ces options est invalide.
static bool take_global_options(int *argc, char **argv)
{
    int kept = 1;
    int verbosity = 0;

    for (int i = 1; i < *argc; i++) {
        if (is_option(argv[i], "-v", "--verbose")) {
            verbosity++;
            continue;
        }
        if (strcmp(argv[i], "-vv") == 0) {
            verbosity += 2;
            continue;
        }
        if (strcmp(argv[i], "--log-level") == 0 && i + 1 < *argc) {
            LogLevel level;

            if (!log_level_from_string(argv[i + 1], &level)) {
                fprintf(stderr, "erreur: niveau de journal inconnu '%s'"
                                " (debug, info, warn, error)\n", argv[i + 1]);
                return false;
            }
            log_set_level(level);
            i++;
            continue;
        }
        if (strcmp(argv[i], "--color") == 0 && i + 1 < *argc) {
            ColorChoice choice;

            if (!color_choice_from_string(argv[i + 1], &choice)) {
                fprintf(stderr, "erreur: reglage de couleur inconnu '%s'"
                                " (auto, always, never)\n", argv[i + 1]);
                return false;
            }
            set_color_choice(choice);
            i++;
            continue;
        }
        if (strcmp(argv[i], "--log-file") == 0 && i + 1 < *argc) {
            std::string error;

            if (!log_open_file(argv[i + 1], &error)) {
                fprintf(stderr, "erreur: %s\n", error.c_str());
                return false;
            }
            i++;
            continue;
        }
        argv[kept++] = argv[i];
    }

    // Chaque -v descend d'un cran: warn par defaut, puis info, puis debug.
    if (verbosity == 1)
        log_set_level(LOG_INFO);
    else if (verbosity >= 2)
        log_set_level(LOG_DEBUG);

    *argc = kept;
    return true;
}

int main(int argc, char **argv)
{
    if (!take_global_options(&argc, argv))
        return 1;

    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (is_option(argv[1], "-V", "--version")) {
        printf("%s\n", MYSNIFFER_VERSION);
        return 0;
    }
    if (is_option(argv[1], "-h", "--help")) {
        print_usage();
        return 0;
    }

    if (strcmp(argv[1], "interfaces") == 0)
        return run_interfaces(argc, argv);
    if (strcmp(argv[1], "capture") == 0)
        return run_capture(argc, argv);
    if (strcmp(argv[1], "read") == 0)
        return run_read(argc, argv);
    if (strcmp(argv[1], "analyze") == 0)
        return run_analyze(argc, argv);

    fprintf(stderr, "erreur: commande inconnue '%s'\n", argv[1]);
    fprintf(stderr, "Essayez 'mysniffer --help'.\n");
    log_close();
    return 1;
}
