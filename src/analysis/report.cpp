#include "analysis/analysis.hpp"

#include <stdlib.h>

#include <algorithm>

#include "dissect/ipv4.hpp"

static Alert make_alert(const std::string &kind, const std::string &message)
{
    Alert alert;

    alert.kind = kind;
    alert.message = message;
    return alert;
}

// --- 1. beaucoup de requetes vers un meme service -------------------------

static void report_busy_services(const Analysis &analysis, std::vector<Alert> *alerts)
{
    // Le debit, et non le compte brut. Une page web consultee pendant dix
    // minutes echange facilement 800 paquets sans rien d'anormal; les memes
    // 800 paquets en deux secondes sont un balayage. Comparer les deux
    // situations au meme nombre ferait crier le detecteur sur chaque site
    // visite, et on apprendrait vite a ne plus le lire.
    //
    // Le debit se mesure sur la fenetre propre au service, pas sur toute la
    // capture: un pic d'une seconde au milieu de dix minutes doit rester
    // visible, et non se faire diluer par la moyenne.
    std::map<ServiceKey, ServiceCounters>::const_iterator it;

    for (it = analysis.services.begin(); it != analysis.services.end(); ++it) {
        long requests = it->second.requests;

        if (requests <= analysis.settings.max_requests)
            continue;

        long duration = it->second.last_seconds - it->second.first_seconds;

        if (duration < 1)
            duration = 1;

        long rate = requests / duration;

        if (rate < analysis.settings.max_requests_per_second)
            continue;

        alerts->push_back(make_alert("requetes",
            ipv4_to_string(it->first.address) + " port " + std::to_string(it->first.port)
            + " a recu " + std::to_string(requests) + " paquets en "
            + std::to_string(duration) + " s, soit " + std::to_string(rate)
            + " par seconde (seuil " + std::to_string(analysis.settings.max_requests_per_second)
            + ")"));
    }
}

// --- 2. beaucoup d'erreurs en retour --------------------------------------

static void report_failing_services(const Analysis &analysis, std::vector<Alert> *alerts)
{
    std::map<ServiceKey, ServiceCounters>::const_iterator it;

    for (it = analysis.services.begin(); it != analysis.services.end(); ++it) {
        if (it->second.errors <= analysis.settings.max_errors)
            continue;

        alerts->push_back(make_alert("erreurs",
            ipv4_to_string(it->first.address) + " port " + std::to_string(it->first.port)
            + " a refuse " + std::to_string(it->second.errors) + " connexions"
            + " (paquets RST, seuil " + std::to_string(analysis.settings.max_errors) + ")"));
    }
}

// --- 3. pics de trafic ----------------------------------------------------

static void report_spikes(const Analysis &analysis, std::vector<Alert> *alerts)
{
    // Il faut assez de secondes pour qu'une moyenne veuille dire quelque chose.
    if (analysis.packets_per_second.size() < 5)
        return;

    long total = 0;
    std::map<long, long>::const_iterator it;

    for (it = analysis.packets_per_second.begin();
         it != analysis.packets_per_second.end(); ++it) {
        total += it->second;
    }

    long average = total / static_cast<long>(analysis.packets_per_second.size());

    if (average < 1)
        return;

    long threshold = average * analysis.settings.spike_factor;
    long spikes = 0;
    long worst = 0;

    for (it = analysis.packets_per_second.begin();
         it != analysis.packets_per_second.end(); ++it) {
        if (it->second <= threshold)
            continue;
        spikes++;
        if (it->second > worst)
            worst = it->second;
    }

    if (spikes == 0)
        return;

    alerts->push_back(make_alert("pic",
        std::to_string(spikes) + " seconde(s) au-dessus de "
        + std::to_string(threshold) + " paquets, jusqu'a " + std::to_string(worst)
        + ", alors que la moyenne est de " + std::to_string(average) + " par seconde"));
}

// --- 4. connexions vers l'exterieur ---------------------------------------

// Pour trier les destinations de la plus bavarde a la moins bavarde.
struct DestinationCount {
    Ipv4 address;
    long packets;
};

static bool more_packets_first(const DestinationCount &a, const DestinationCount &b)
{
    return a.packets > b.packets;
}

static void report_outside(const Analysis &analysis, std::vector<Alert> *alerts)
{
    if (analysis.outside_destinations.empty())
        return;

    std::vector<DestinationCount> sorted;
    std::map<Ipv4, long>::const_iterator it;

    for (it = analysis.outside_destinations.begin();
         it != analysis.outside_destinations.end(); ++it) {
        // Les reseaux declares connus ne sont pas signales: c'est ce qui
        // permet de parler de connexion "non autorisee" et non d'un simple
        // inventaire de tout ce qui sort.
        if (analysis_is_allowed(analysis.settings, it->first))
            continue;

        DestinationCount entry;

        entry.address = it->first;
        entry.packets = it->second;
        sorted.push_back(entry);
    }

    if (sorted.empty())
        return;
    std::sort(sorted.begin(), sorted.end(), more_packets_first);

    // On ne peut pas savoir ce qui est autorise sans qu'on nous le dise: on
    // liste donc les adresses publiques contactees, a l'utilisateur de
    // reconnaitre celles qui n'ont rien a faire la.
    std::string message = std::to_string(sorted.size())
                        + " adresse(s) publique(s) non declaree(s), les plus actives: ";

    for (size_t i = 0; i < sorted.size() && i < 5; i++) {
        if (i > 0)
            message += ", ";
        message += ipv4_to_string(sorted[i].address) + " ("
                 + std::to_string(sorted[i].packets) + ")";
    }

    alerts->push_back(make_alert("exterieur", message));
}

// --- 6. intervalles reguliers ---------------------------------------------

// Un programme qui appelle chez lui le fait a intervalle fixe, parce qu'il
// dort entre deux appels. Un humain qui navigue, jamais.
//
// On mesure donc a quel point les ecarts s'ecartent de leur moyenne. Un
// resultat proche de zero signe une regularite de machine.
//
// Deux filtres evitent de crier au loup, et tous deux viennent de l'epreuve
// du trafic reel.
//
// D'abord, on ne retient que les destinations publiques. A l'interieur du
// reseau, la regularite est la norme: une machine interroge son serveur DNS
// ou son serveur de temps a heure fixe.
//
// Ensuite, on ignore les intervalles courts. Une connexion HTTPS active
// envoie des paquets chaque seconde, ce qui parait parfaitement regulier
// alors que c'est simplement une page en train de charger. Une vraie balise
// dort entre deux appels, d'ou un intervalle d'au moins quelques dizaines de
// secondes. Sans ce filtre, chaque onglet ouvert declenchait une alerte.
static void report_beacons(const Analysis &analysis, std::vector<Alert> *alerts)
{
    std::map<ConversationKey, ConversationCounters>::const_iterator it;

    for (it = analysis.conversations.begin(); it != analysis.conversations.end(); ++it) {
        const std::vector<long> &gaps = it->second.gaps;

        if (static_cast<long>(gaps.size()) < analysis.settings.min_beacon_samples)
            continue;
        if (!ipv4_is_public(it->first.destination))
            continue;
        // Un serveur de temps public repond a intervalle fixe par nature.
        // C'est exactement ce que la liste des reseaux connus sert a taire.
        if (analysis_is_allowed(analysis.settings, it->first.destination))
            continue;

        long total = 0;

        for (size_t i = 0; i < gaps.size(); i++)
            total += gaps[i];

        long average = total / static_cast<long>(gaps.size());

        if (average < analysis.settings.min_beacon_interval)
            continue;

        // Ecart moyen a la moyenne, exprime en pourcentage de celle-ci.
        long deviation = 0;

        for (size_t i = 0; i < gaps.size(); i++)
            deviation += labs(gaps[i] - average);
        deviation = (deviation * 100) / (static_cast<long>(gaps.size()) * average);

        if (deviation > analysis.settings.beacon_tolerance)
            continue;

        alerts->push_back(make_alert("balise",
            ipv4_to_string(it->first.source) + " contacte "
            + ipv4_to_string(it->first.destination) + " port "
            + std::to_string(it->first.port) + " toutes les "
            + std::to_string(average) + " s environ ("
            + std::to_string(gaps.size()) + " mesures, ecart de "
            + std::to_string(deviation) + "%)"));
    }
}

// --------------------------------------------------------------------------

std::vector<Alert> analysis_report(const Analysis &analysis)
{
    std::vector<Alert> alerts;

    report_busy_services(analysis, &alerts);
    report_failing_services(analysis, &alerts);
    report_spikes(analysis, &alerts);
    report_outside(analysis, &alerts);

    // Le protocole inattendu sur un port standard est repere au vol, pendant
    // la collecte, parce qu'il demande de regarder le contenu des paquets.
    for (size_t i = 0; i < analysis.port_alerts.size(); i++)
        alerts.push_back(analysis.port_alerts[i]);

    report_beacons(analysis, &alerts);
    return alerts;
}
