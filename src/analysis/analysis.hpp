#pragma once

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "dissect/decode.hpp"
#include "net/ipv4_address.hpp"

// Detection de comportements anormaux.
//
// Le principe est simple: on donne les paquets un par un a l'analyseur, qui
// remplit des compteurs, puis on lui demande son verdict a la fin. Il ne
// decide rien en cours de route, parce que la plupart des anomalies ne se
// voient qu'en regardant l'ensemble: un pic de trafic n'a de sens que compare
// a la moyenne, et un intervalle regulier ne se voit qu'apres plusieurs mesures.
//
// Les six comportements cherches sont ceux que le sujet cite:
//
//   1. beaucoup de requetes vers un meme service;
//   2. beaucoup d'erreurs en retour d'un service;
//   3. pics de trafic inattendus;
//   4. connexions vers des adresses exterieures au reseau local;
//   5. protocole inattendu sur un port standard;
//   6. intervalles reguliers, signe d'un programme qui appelle chez lui.

// Un reseau que l'utilisateur declare connu et legitime.
//
// Sans cette notion, le programme ne peut pas parler de connexion "non
// autorisee" comme le demande le sujet: il ne sait pas ce qui est autorise.
// Il se contenterait d'inventorier tout ce qui sort, ce qui n'apprend rien.
struct AllowedNetwork {
    Ipv4 address;
    int prefix_length;
};

// Les seuils, tous reglables depuis la ligne de commande. Les valeurs par
// defaut conviennent a une capture de quelques minutes sur un poste ordinaire.
struct AnalysisSettings {
    // Un service est juge trop sollicite s'il recoit a la fois beaucoup de
    // paquets EN TOUT et beaucoup de paquets PAR SECONDE. Le debit est le
    // critere qui compte: 800 paquets en dix minutes, c'est une page web;
    // 800 paquets en deux secondes, c'est un balayage.
    long max_requests;            // nombre minimal pour qu'on s'y interesse
    long max_requests_per_second; // au-dela de ce debit, on signale

    long max_errors;          // au-dela, un service renvoie trop d'erreurs
    long spike_factor;        // une seconde est un pic si elle depasse N fois la moyenne
    long min_beacon_samples;  // nombre d'intervalles avant de juger une regularite
    long min_beacon_interval; // en secondes: en dessous, ce n'est pas une balise
    long beacon_tolerance;    // en pourcentage: en dessous, les intervalles sont reguliers

    // Les reseaux declares connus. Les adresses qui en font partie ne sont
    // signalees ni comme exterieures, ni comme balises: c'est ce qui permet
    // de taire le serveur de temps de l'entreprise sans taire le reste.
    std::vector<AllowedNetwork> allowed;
};

// Vrai si cette adresse appartient a un reseau declare connu.
bool analysis_is_allowed(const AnalysisSettings &settings, Ipv4 address);

AnalysisSettings default_analysis_settings(void);

// Une anomalie constatee.
struct Alert {
    std::string kind;     // "requetes", "erreurs", "pic", "exterieur", "port", "balise"
    std::string message;  // la phrase a afficher
};

// Un service vise: une machine et un port.
struct ServiceKey {
    Ipv4 address;
    uint16_t port;
};

bool operator<(const ServiceKey &a, const ServiceKey &b);

// Une conversation: qui parle a qui, et sur quel port.
struct ConversationKey {
    Ipv4 source;
    Ipv4 destination;
    uint16_t port;
};

bool operator<(const ConversationKey &a, const ConversationKey &b);

// Ce qu'on retient d'un service.
struct ServiceCounters {
    long requests;  // paquets recus
    long errors;    // refus renvoyes: paquets RST de TCP

    // Quand ce service a ete vu pour la premiere et la derniere fois.
    // Le debit se mesure sur CETTE fenetre et non sur toute la capture:
    // sinon un pic d'une seconde noye dans dix minutes disparaitrait.
    long first_seconds;
    long last_seconds;
};

// Ce qu'on retient d'une conversation, pour reperer les appels reguliers.
struct ConversationCounters {
    long packets;
    long last_seconds;          // date du dernier paquet vu
    std::vector<long> gaps;     // ecarts entre paquets consecutifs, en secondes
};

// L'etat de l'analyse en cours.
struct Analysis {
    AnalysisSettings settings;

    long total_packets;
    long first_seconds;
    long last_seconds;

    std::map<ServiceKey, ServiceCounters> services;
    std::map<ConversationKey, ConversationCounters> conversations;
    std::map<long, long> packets_per_second;   // seconde -> nombre de paquets
    std::map<Ipv4, long> outside_destinations; // adresse publique -> nombre de paquets
    std::vector<Alert> port_alerts;            // reperes au vol, voir analysis.cpp
};

// Prepare une analyse vide.
Analysis analysis_start(const AnalysisSettings &settings);

// Donne un paquet a l'analyseur.
//
// "data" et "size" sont le paquet brut: ils servent a regarder le debut des
// donnees pour reconnaitre le protocole applicatif, ce que le paquet decode
// ne contient pas.
void analysis_add(Analysis *analysis, const DecodedPacket &packet,
                  const uint8_t *data, size_t size, long seconds);

// Rend les anomalies constatees. A appeler une fois, a la fin.
std::vector<Alert> analysis_report(const Analysis &analysis);
