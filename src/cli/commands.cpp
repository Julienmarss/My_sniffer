#include "cli/commands.hpp"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include "capture/interface.hpp"
#include "dissect/decode.hpp"
#include "dissect/summary.hpp"
#include "filter/filter.hpp"
#include "log/log.hpp"
#include "storage/pcap.hpp"
#include "term/color.hpp"

// Mis a 1 quand l'utilisateur appuie sur Ctrl+C. La boucle de capture le
// regarde a chaque tour et s'arrete proprement, ce qui laisse le temps
// d'afficher le bilan au lieu de couper net.
static volatile sig_atomic_t stop_requested = 0;

// Reglage de couleur demande sur la ligne de commande. Il suit le meme
// principe que le niveau de journal: fixe une fois au demarrage, puis lu par
// tout ce qui affiche. Ca evite de le faire traverser les trois structures
// d'options et toutes les fonctions qui les portent.
static ColorChoice color_choice = COLOR_AUTO;

void set_color_choice(ColorChoice choice)
{
    color_choice = choice;
}

static void on_interrupt(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
    // On n'ecrit surtout pas dans le journal ici: un gestionnaire de signal
    // ne doit appeler que des fonctions prevues pour, et fprintf n'en est pas.
    // Le message est ecrit par la boucle, quand elle constate l'arret.
}

// Installe le gestionnaire de Ctrl+C.
//
// On passe par sigaction et NON par signal(). La raison est capitale: sur
// Linux, signal() pose l'option SA_RESTART, qui fait redemarrer toute seule la
// lecture bloquante apres le signal. Le Ctrl+C resterait alors sans effet tant
// qu'aucun paquet n'arrive, ce qui donne l'impression d'un programme fige sur
// une interface calme.
//
// Windows n'a pas sigaction: signal() y suffit, ce probleme de redemarrage
// automatique etant propre a POSIX. Ca ne suffit pas a interrompre net une
// capture Npcap bloquee: capture_windows.cpp gere ce cas separement avec son
// propre gestionnaire de console, qui verifie le drapeau a intervalles
// reguliers au lieu de compter sur une lecture interrompue.
static void install_interrupt_handler(void)
{
#if defined(_WIN32)
    signal(SIGINT, on_interrupt);
#else
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = on_interrupt;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;  // surtout pas SA_RESTART
    sigaction(SIGINT, &action, NULL);
#endif
}

// ------------------------------------------------------------- affichage

// Texte de la colonne "etat": "up running loopback"...
static std::string status_text(const Interface &card)
{
    std::string text;

    text += card.is_up ? "up" : "down";
    if (card.is_running)
        text += " running";
    if (card.is_loopback)
        text += " loopback";
    return text;
}

// Texte de la colonne "adresses": "192.168.1.10/24, 10.0.0.1/8".
static std::string addresses_text(const Interface &card)
{
    std::string text;

    for (size_t i = 0; i < card.addresses.size(); i++) {
        if (i > 0)
            text += ", ";
        text += ipv4_to_string(card.addresses[i].ip);
        if (card.addresses[i].prefix_length >= 0) {
            text += "/";
            text += std::to_string(card.addresses[i].prefix_length);
        }
    }
    if (text.empty())
        text = "-";
    return text;
}

// Affiche une ligne pour un paquet, et compte les sommes de controle douteuses.
//
// Les deux commandes capture et read passent par ici, pour que le direct et la
// relecture d'un fichier disent exactement la meme chose du meme paquet.
// Affiche le paquet s'il repond a la regle, et dit s'il a ete garde.
//
// Le paquet n'est decode qu'une fois: le filtre et l'affichage se servent du
// meme resultat. C'est aussi pour ca que le filtrage ne coute presque rien.
static bool show_packet(const CapturedPacket &packet, const SummaryOptions &options,
                        const Filter &filter, long *checksum_problems)
{
    DecodedPacket decoded = decode_packet(packet.data, packet.length);

    if (!filter_matches(filter, decoded))
        return false;

    PacketSummary summary = summarize_packet(decoded, packet.seconds,
                                             packet.microseconds, options);

    // Si le paquet etait plus grand que ce qu'on a pu lire, on le signale
    // plutot que de laisser croire qu'il etait court.
    if (packet.original_length > packet.length) {
        summary.line += "  [tronque, " + std::to_string(packet.original_length)
                      + " sur le cable]";
    }

    if (summary.checksum_problem)
        (*checksum_problems)++;
    printf("%s\n", summary.line.c_str());
    return true;
}

// Affiche le bilan de fin, identique pour les deux commandes.
static void show_report(const char *what, long kept, long seen, unsigned long dropped,
                        long checksum_problems, bool filter_is_absent)
{
    Palette palette = choose_palette(color_choice);

    if (checksum_problems > 0)
        printf("\n%s\n", paint(palette, palette.dim, checksum_explanation()).c_str());

    printf("\n%ld paquet(s) %s", kept, what);
    if (!filter_is_absent)
        printf(" sur %ld examine(s)", seen);

    // Des paquets perdus veulent dire que le programme n'a pas suivi le debit:
    // c'est la seule ligne du bilan qui merite qu'on la remarque.
    if (dropped > 0) {
        printf(", %s", paint(palette, palette.alert,
                             std::to_string(dropped) + " perdu(s) par le systeme").c_str());
    }
    printf(".\n");
}

// ------------------------------------------------------------ interfaces

int command_interfaces(bool show_all)
{
    std::string error;
    std::vector<Interface> cards = list_interfaces(&error);

    if (!error.empty()) {
        fprintf(stderr, "erreur: %s\n", error.c_str());
        return 1;
    }

    printf("%-16s %5s  %-17s  %-20s  %s\n", "NOM", "INDEX", "MAC", "ETAT", "ADRESSES");

    int shown = 0;

    for (size_t i = 0; i < cards.size(); i++) {
        if (!show_all && !interface_is_capturable(cards[i]))
            continue;

        std::string mac = cards[i].has_mac ? mac_to_string(cards[i].mac) : "-";

        printf("%-16s %5u  %-17s  %-20s  %s\n", cards[i].name.c_str(), cards[i].index,
               mac.c_str(), status_text(cards[i]).c_str(),
               addresses_text(cards[i]).c_str());
        shown++;
    }

    if (shown == 0)
        printf("(aucune interface capturable, essayez --all)\n");
    return 0;
}

// --------------------------------------------------------------- capture

// Choisit une interface quand l'utilisateur n'en a pas donne.
static bool pick_default_interface(std::string *name, std::string *error)
{
    std::vector<Interface> cards = list_interfaces(error);

    if (!error->empty())
        return false;

    // On prefere une interface qui a du trafic: activee ET connectee.
    for (size_t i = 0; i < cards.size(); i++) {
        if (interface_is_capturable(cards[i]) && cards[i].is_running) {
            *name = cards[i].name;
            return true;
        }
    }
    for (size_t i = 0; i < cards.size(); i++) {
        if (interface_is_capturable(cards[i])) {
            *name = cards[i].name;
            return true;
        }
    }

    *error = "aucune interface utilisable pour la capture";
    return false;
}

// Retient les adresses des cartes de cette machine, pour reconnaitre plus tard
// les paquets qu'elle emet. Voir SummaryOptions pour la raison.
static SummaryOptions local_summary_options(void)
{
    SummaryOptions options;
    std::vector<Interface> cards = list_interfaces(NULL);

    options.palette = choose_palette(color_choice);

    for (size_t i = 0; i < cards.size(); i++) {
        if (cards[i].has_mac)
            options.local_macs.push_back(cards[i].mac);
    }
    return options;
}

// La boucle de capture elle-meme. Rend le code de sortie.
static int capture_loop(Capture *capture, PcapWriter *writer, const Filter &filter,
                        const CaptureOptions &settings)
{
    SummaryOptions options = local_summary_options();
    std::string error;
    long checksum_problems = 0;
    long seen = 0;
    long captured = 0;

    while (!stop_requested && (settings.count <= 0 || captured < settings.count)) {
        CapturedPacket packet;
        DecodedPacket decoded;

        if (!capture_next(capture, &packet, &error)) {
            // Un message vide veut dire "interrompu par un signal", pas une
            // panne: on sort sans rien dire.
            if (stop_requested || error.empty())
                break;
            fprintf(stderr, "erreur: %s\n", error.c_str());
            return 1;
        }

        seen++;

        if (writer->file != NULL) {
            // Quand on enregistre, on n'affiche pas chaque paquet: la sortie
            // defilerait trop vite et ralentirait la capture. Le filtre
            // s'applique quand meme, pour n'ecrire que ce qui interesse.
            decoded = decode_packet(packet.data, packet.length);
            if (!filter_matches(filter, decoded))
                continue;

            if (!pcap_writer_write(writer, packet.data, packet.length,
                                   packet.original_length, packet.seconds,
                                   packet.microseconds, &error)) {
                fprintf(stderr, "erreur: %s\n", error.c_str());
                return 1;
            }
        } else if (!show_packet(packet, options, filter, &checksum_problems)) {
            continue;
        }
        captured++;
    }

    unsigned long dropped = capture_dropped(capture);

    if (stop_requested)
        log_write(LOG_INFO, "arret demande par l'utilisateur");
    if (dropped > 0) {
        log_write(LOG_WARN, "%lu paquet(s) perdu(s) par le systeme: le programme"
                            " n'a pas suivi le debit", dropped);
    }
    log_write(LOG_INFO, "capture terminee: %ld paquet(s) gardes sur %ld examines",
              captured, seen);

    show_report("capture(s)", captured, seen, dropped,
                checksum_problems, filter_is_empty(filter));
    return 0;
}

int command_capture(const CaptureOptions &settings)
{
    std::string name = settings.interface_name;
    std::string error;
    Filter filter;

    // On analyse la regle avant d'ouvrir quoi que ce soit: inutile de demander
    // des privileges pour decouvrir ensuite que la regle est mal ecrite.
    if (!filter_parse(settings.filter, &filter, &error)) {
        log_write(LOG_ERROR, "filtre invalide: %s", error.c_str());
        fprintf(stderr, "erreur dans le filtre: %s\n", error.c_str());
        return 1;
    }

    if (name.empty() && !pick_default_interface(&name, &error)) {
        fprintf(stderr, "erreur: %s\n", error.c_str());
        return 1;
    }

    Capture capture;

    if (!capture_open(&capture, name, settings.promiscuous, &error)) {
        log_write(LOG_ERROR, "ouverture de %s impossible: %s", name.c_str(), error.c_str());
        fprintf(stderr, "erreur: %s\n", error.c_str());
        return 1;
    }

    // On ouvre le fichier avant de commencer: inutile de capturer pour
    // decouvrir ensuite qu'on ne peut pas ecrire.
    PcapWriter writer = {NULL, 0};

    if (!settings.output_path.empty()
        && !pcap_writer_open(&writer, settings.output_path, &error)) {
        fprintf(stderr, "erreur: %s\n", error.c_str());
        capture_close(&capture);
        return 1;
    }

    log_write(LOG_INFO, "capture ouverte sur %s, mode espion %s",
              name.c_str(), settings.promiscuous ? "actif" : "inactif");

    // Ces messages vont sur la sortie d'erreur et non sur la sortie standard.
    // C'est ce que fait tcpdump, et pour la meme raison: la sortie standard ne
    // doit contenir que le resultat, pour qu'on puisse la rediriger proprement.
    fprintf(stderr, "Ecoute sur %s%s. Ctrl+C pour arreter.\n",
            name.c_str(), settings.promiscuous ? " (mode espion)" : "");
    if (writer.file != NULL)
        fprintf(stderr, "Enregistrement dans %s (les paquets ne defilent pas a l'ecran).\n",
                settings.output_path.c_str());

    install_interrupt_handler();

    int exit_code = capture_loop(&capture, &writer, filter, settings);

    if (writer.file != NULL) {
        fprintf(stderr, "Ecrit dans %s.\n", settings.output_path.c_str());
        pcap_writer_close(&writer);
    }
    capture_close(&capture);
    return exit_code;
}

// ------------------------------------------------------------------ read

int command_read(const ReadOptions &settings)
{
    if (settings.path.empty()) {
        fprintf(stderr, "erreur: indiquez le fichier a lire avec -r\n");
        return 1;
    }

    PcapReader reader;
    std::string error;
    Filter filter;

    if (!filter_parse(settings.filter, &filter, &error)) {
        log_write(LOG_ERROR, "filtre invalide: %s", error.c_str());
        fprintf(stderr, "erreur dans le filtre: %s\n", error.c_str());
        return 1;
    }

    if (!pcap_reader_open(&reader, settings.path, &error)) {
        log_write(LOG_ERROR, "lecture de %s impossible: %s",
                  settings.path.c_str(), error.c_str());
        fprintf(stderr, "erreur: %s\n", error.c_str());
        return 1;
    }

    log_write(LOG_INFO, "lecture du fichier %s", settings.path.c_str());

    // Un fichier ne dit pas quelle carte l'a produit. Mais si la capture a ete
    // faite sur cette machine, ce qui est le cas courant, une de nos cartes
    // apparait comme source. On les compare donc, ce qui rend la relecture
    // coherente avec la capture en direct. Si le fichier vient d'ailleurs,
    // aucune ne correspond et rien ne change.
    SummaryOptions options = local_summary_options();
    long shown = 0;
    long seen = 0;
    long checksum_problems = 0;
    int exit_code = 0;

    while (settings.count <= 0 || shown < settings.count) {
        CapturedPacket packet;
        bool end = false;

        if (!pcap_reader_next(&reader, &packet, &end, &error)) {
            fprintf(stderr, "erreur: %s\n", error.c_str());
            exit_code = 1;
            break;
        }
        if (end)
            break;

        seen++;
        if (show_packet(packet, options, filter, &checksum_problems))
            shown++;
    }

    show_report("lu(s)", shown, seen, 0, checksum_problems, filter_is_empty(filter));
    pcap_reader_close(&reader);
    return exit_code;
}

// ---------------------------------------------------------------- analyze

// Affiche le resultat de l'analyse.
static void show_alerts(const std::vector<Alert> &alerts, long packets, long duration)
{
    printf("\n%ld paquet(s) examine(s)", packets);
    if (duration > 0)
        printf(" sur %ld seconde(s)", duration);
    printf(".\n\n");

    if (alerts.empty()) {
        printf("Aucun comportement anormal detecte.\n");
        return;
    }

    Palette palette = choose_palette(color_choice);

    printf("%zu observation(s):\n\n", alerts.size());
    for (size_t i = 0; i < alerts.size(); i++) {
        std::string kind = "[" + pad_right(alerts[i].kind, 9) + "]";

        printf("  %s %s\n", paint(palette, palette.alert, kind).c_str(),
               alerts[i].message.c_str());
    }

    printf("\n%s\n", paint(palette, palette.dim,
        "Ces observations ne sont pas des preuves: ce sont des ecarts a\n"
        "l'ordinaire. Voir 'mysniffer analyze --help' pour regler les seuils,\n"
        "et --allow pour declarer connus les reseaux qui n'ont rien a se reprocher.").c_str());
}

int command_analyze(const AnalyzeOptions &settings)
{
    std::string error;
    Filter filter;

    if (!filter_parse(settings.filter, &filter, &error)) {
        fprintf(stderr, "erreur dans le filtre: %s\n", error.c_str());
        return 1;
    }

    Analysis analysis = analysis_start(settings.settings);
    long examined = 0;

    if (!settings.path.empty()) {
        // Analyse d'un fichier deja enregistre: aucun privilege necessaire.
        PcapReader reader;

        if (!pcap_reader_open(&reader, settings.path, &error)) {
            fprintf(stderr, "erreur: %s\n", error.c_str());
            return 1;
        }

        while (settings.count <= 0 || examined < settings.count) {
            CapturedPacket packet;
            bool end = false;

            if (!pcap_reader_next(&reader, &packet, &end, &error)) {
                fprintf(stderr, "erreur: %s\n", error.c_str());
                pcap_reader_close(&reader);
                return 1;
            }
            if (end)
                break;

            DecodedPacket decoded = decode_packet(packet.data, packet.length);

            if (!filter_matches(filter, decoded))
                continue;
            analysis_add(&analysis, decoded, packet.data, packet.length, packet.seconds);
            examined++;
        }
        pcap_reader_close(&reader);
    } else {
        // Analyse en direct: on capture jusqu'a Ctrl+C ou jusqu'au compte.
        std::string name = settings.interface_name;

        if (name.empty() && !pick_default_interface(&name, &error)) {
            fprintf(stderr, "erreur: %s\n", error.c_str());
            return 1;
        }

        Capture capture;

        if (!capture_open(&capture, name, true, &error)) {
            fprintf(stderr, "erreur: %s\n", error.c_str());
            return 1;
        }

        log_write(LOG_INFO, "capture ouverte sur %s pour analyse", name.c_str());

        fprintf(stderr, "Analyse du trafic sur %s. Ctrl+C pour arreter.\n", name.c_str());
        install_interrupt_handler();

        while (!stop_requested && (settings.count <= 0 || examined < settings.count)) {
            CapturedPacket packet;

            if (!capture_next(&capture, &packet, &error)) {
                if (stop_requested || error.empty())
                    break;
                fprintf(stderr, "erreur: %s\n", error.c_str());
                capture_close(&capture);
                return 1;
            }

            DecodedPacket decoded = decode_packet(packet.data, packet.length);

            if (!filter_matches(filter, decoded))
                continue;
            analysis_add(&analysis, decoded, packet.data, packet.length, packet.seconds);
            examined++;
        }

        unsigned long dropped = capture_dropped(&capture);

        if (stop_requested)
            log_write(LOG_INFO, "arret demande par l'utilisateur");
        if (dropped > 0) {
            log_write(LOG_WARN, "%lu paquet(s) perdu(s) par le systeme: l'analyse"
                                " porte donc sur un trafic incomplet", dropped);
            fprintf(stderr, "Attention: %lu paquet(s) perdu(s) par le systeme.\n", dropped);
        }
        capture_close(&capture);
    }

    long duration = analysis.last_seconds - analysis.first_seconds;

    std::vector<Alert> alerts = analysis_report(analysis);

    // On ne recopie pas les alertes dans le journal: ce sont le RESULTAT du
    // programme, et elles sortent deja sur la sortie standard. Les repeter
    // ferait apparaitre chaque observation deux fois a l'ecran.
    log_write(LOG_INFO, "analyse terminee: %ld paquet(s), %zu observation(s)",
              examined, alerts.size());

    show_alerts(alerts, examined, duration);
    return 0;
}

const char *checksum_explanation(void)
{
    return "Note: une somme de controle invalide ne veut presque jamais dire que le\n"
           "paquet est abime. Sur du materiel moderne, la carte reseau s'occupe elle-meme\n"
           "des sommes de controle, dans les deux sens:\n"
           "  - a l'envoi, elle la calcule juste avant de mettre la trame sur le cable,\n"
           "    donc apres notre capture: le champ est encore vide quand on le lit;\n"
           "  - a la reception, elle verifie la somme puis fusionne plusieurs trames en\n"
           "    un seul gros paquet, dont la somme n'a plus de sens.\n"
           "C'est ce second cas qui explique les paquets annonces a plus de 1500 octets.";
}
