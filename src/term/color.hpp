#pragma once

#include <string>

// Couleurs du terminal.
//
// On n'utilise aucune bibliotheque. Une couleur, dans un terminal, c'est juste
// une suite de caracteres que le terminal interprete au lieu de l'afficher:
// "\033[36m" veut dire "ecris en cyan a partir d'ici", "\033[0m" veut dire
// "reviens au reglage normal". C'est tout.
//
// La palette nomme les ROLES, pas les couleurs: "address", pas "cyan". Le code
// qui affiche dit ce qu'il affiche, et la couleur reelle se change a un seul
// endroit.
//
// Quand la couleur est eteinte, chaque champ vaut la chaine vide. Le code qui
// affiche reste alors exactement le meme: il colle des chaines vides au lieu
// de codes. Il n'y a donc pas deux chemins a tester, un en couleur et un sans.
struct Palette {
    // Les valeurs par defaut sont vides: une palette construite sans rien dire
    // n'affiche aucune couleur. Sans ces "= ", les champs seraient des
    // pointeurs au hasard et le programme planterait.
    const char *dim = "";       // heure, adresses MAC, annotations: le decor
    const char *address = "";   // adresses IP et ports: ce qu'on lit vraiment
    const char *protocol = "";  // TCP, UDP, ARP...
    const char *flags = "";     // les drapeaux TCP
    const char *alert = "";     // ce qui ne va pas
    const char *reset = "";     // retour au reglage normal du terminal
};

// Ce que l'utilisateur a demande sur la ligne de commande.
enum ColorChoice {
    COLOR_AUTO,    // couleur seulement si la sortie est un vrai terminal
    COLOR_ALWAYS,  // couleur meme vers un fichier (utile pour "less -R")
    COLOR_NEVER
};

// Lit "auto", "always" ou "never". Retourne false pour tout le reste.
bool color_choice_from_string(const char *text, ColorChoice *out);

// Decide s'il faut colorer la sortie standard, et rend la palette qui va avec.
Palette choose_palette(ColorChoice choice);

// Entoure un texte des codes d'une couleur.
// Quand la couleur est eteinte, les deux codes sont vides et le texte ressort
// inchange.
std::string paint(const Palette &palette, const char *color, const std::string &text);

// Complete un texte avec des espaces pour atteindre une largeur donnee.
//
// Le remplissage se fait AVANT la mise en couleur, jamais apres: les codes de
// couleur occupent des octets que le terminal n'affiche pas, donc les compter
// dans la largeur decalerait toutes les colonnes.
std::string pad_right(const std::string &text, size_t width);
