#pragma once

#include <string>
#include <vector>

#include "analysis/analysis.hpp"
#include "term/color.hpp"

// Les quatre commandes du programme. Chacune rend le code de sortie a donner
// au systeme: 0 si tout va bien, 1 en cas de probleme.
//
// Elles sont ici et non dans main.cpp pour que main ne fasse qu'une chose:
// lire la ligne de commande et aiguiller.

// Options de la commande capture.
struct CaptureOptions {
    std::string interface_name;  // vide: on choisit une interface tout seuls
    std::string output_path;     // vide: on affiche au lieu d'enregistrer
    std::string filter;          // vide: on garde tous les paquets
    long count;                  // 0 ou moins: sans limite
    bool promiscuous;
};

// Options de la commande read.
struct ReadOptions {
    std::string path;
    std::string filter;          // vide: on garde tous les paquets
    long count;                  // 0 ou moins: tout le fichier
};

// Options de la commande analyze.
struct AnalyzeOptions {
    std::string path;            // un fichier .pcap a relire
    std::string interface_name;  // ou bien une interface a ecouter
    std::string filter;
    long count;
    AnalysisSettings settings;   // seuils et reseaux connus, reglables
};

// Fixe la couleur de l'affichage, avant de lancer une commande.
void set_color_choice(ColorChoice choice);

int command_interfaces(bool show_all);
int command_capture(const CaptureOptions &options);
int command_read(const ReadOptions &options);
int command_analyze(const AnalyzeOptions &options);

// Texte affiche quand des sommes de controle sont tombees a faux. Ce n'est
// presque jamais un paquet abime, et il vaut mieux le dire que laisser
// l'utilisateur croire a un bug.
const char *checksum_explanation(void);
