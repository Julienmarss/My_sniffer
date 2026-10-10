#include "term/color.hpp"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <io.h>
#  include <stdio.h>
#  define isatty _isatty
#  define STDOUT_FILENO _fileno(stdout)
#else
#  include <unistd.h>
#endif

bool color_choice_from_string(const char *text, ColorChoice *out)
{
    if (strcmp(text, "auto") == 0) {
        *out = COLOR_AUTO;
        return true;
    }
    if (strcmp(text, "always") == 0) {
        *out = COLOR_ALWAYS;
        return true;
    }
    if (strcmp(text, "never") == 0) {
        *out = COLOR_NEVER;
        return true;
    }
    return false;
}

// Vrai si mettre de la couleur a un sens ici et maintenant.
static bool colors_make_sense(void)
{
    // Convention repandue entre outils en ligne de commande: si la variable
    // NO_COLOR existe, on n'en met pas. Voir https://no-color.org/. Elle
    // permet de regler la question une fois pour tous les programmes.
    if (getenv("NO_COLOR") != NULL)
        return false;

    // Un terminal qui se declare "dumb" n'interprete pas les codes: il les
    // afficherait tels quels, en plein milieu des paquets.
    const char *term = getenv("TERM");

    if (term != NULL && strcmp(term, "dumb") == 0)
        return false;

    // La question qui compte: est-ce qu'on ecrit vers un terminal, ou vers un
    // fichier ou un tuyau? Dans le second cas les codes saliraient le
    // resultat. C'est ce qui fait que
    //   mysniffer read -r x.pcap > sortie.txt
    //   mysniffer read -r x.pcap | grep 443
    // donnent du texte propre sans qu'on ait rien a demander.
    return isatty(STDOUT_FILENO) == 1;
}

Palette choose_palette(ColorChoice choice)
{
    Palette palette;

    if (choice == COLOR_NEVER)
        return palette;
    if (choice == COLOR_AUTO && !colors_make_sense())
        return palette;

    palette.dim = "\033[90m";       // gris
    palette.address = "\033[36m";   // cyan
    palette.protocol = "\033[33m";  // jaune
    palette.flags = "\033[35m";     // magenta
    palette.alert = "\033[31m";     // rouge
    palette.reset = "\033[0m";
    return palette;
}

std::string paint(const Palette &palette, const char *color, const std::string &text)
{
    // Rien a faire quand la couleur est eteinte: on evite deux concatenations
    // inutiles sur chaque champ de chaque paquet.
    if (color[0] == '\0')
        return text;
    return std::string(color) + text + palette.reset;
}

std::string pad_right(const std::string &text, size_t width)
{
    // Un champ plus long que prevu n'est jamais coupe: on prefere une ligne
    // qui depasse a une adresse tronquee, qui serait un mensonge.
    if (text.size() >= width)
        return text;
    return text + std::string(width - text.size(), ' ');
}
