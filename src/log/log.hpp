#pragma once

#include <string>

// L'attribut format n'existe que chez GCC et Clang: MSVC ne le comprend pas
// du tout et refuse de compiler (pas un simple avertissement ignore, une
// vraie erreur de syntaxe). On le neutralise donc ailleurs.
#if defined(__GNUC__) || defined(__clang__)
#  define FORMAT_PRINTF(format_index, first_arg) \
       __attribute__((format(printf, format_index, first_arg)))
#else
#  define FORMAT_PRINTF(format_index, first_arg)
#endif

enum LogLevel {
    LOG_DEBUG,   // detail utile pour comprendre un probleme
    LOG_INFO,    // evenement normal de la vie du programme
    LOG_WARN,    // quelque chose d'anormal, mais on continue
    LOG_ERROR    // on n'a pas pu faire ce qui etait demande
};

// Les messages en dessous de ce niveau sont jetes. Par defaut: LOG_WARN,
// pour que le programme reste silencieux tant que tout va bien.
void log_set_level(LogLevel level);
LogLevel log_level(void);

// Lit un niveau ecrit en toutes lettres: "debug", "info", "warn", "error".
// Retourne false si le mot n'est pas reconnu.
bool log_level_from_string(const std::string &text, LogLevel *level);

// Envoie le journal dans un fichier au lieu de la sortie d'erreur.
// Le fichier est ouvert en ajout, pour ne pas effacer les sessions passees.
bool log_open_file(const std::string &path, std::string *error);

// Ferme le fichier s'il y en a un. Sans danger si aucun n'a ete ouvert.
void log_close(void);

// Ecrit une ligne, si son niveau le permet.
//
// L'attribut format demande au compilateur de verifier que les arguments
// correspondent au texte, exactement comme il le fait pour printf. Une faute
// devient une erreur de compilation au lieu d'un plantage a l'execution.
void log_write(LogLevel level, const char *format, ...) FORMAT_PRINTF(2, 3);
