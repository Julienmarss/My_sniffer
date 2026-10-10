#include "log/log.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// localtime_r n'existe pas sous Windows: MSVC fournit localtime_s, avec les
// arguments dans l'autre ordre et un code d'erreur plutot qu'un pointeur.
static bool portable_localtime(const time_t *when, struct tm *broken)
{
#if defined(_WIN32)
    return localtime_s(broken, when) == 0;
#else
    return localtime_r(when, broken) != NULL;
#endif
}

static LogLevel g_level = LOG_WARN;

static FILE *g_stream = NULL;
static bool g_owns_stream = false;

static FILE *current_stream(void)
{
    return (g_stream != NULL) ? g_stream : stderr;
}

void log_set_level(LogLevel level)
{
    g_level = level;
}

LogLevel log_level(void)
{
    return g_level;
}

bool log_level_from_string(const std::string &text, LogLevel *level)
{
    if (text == "debug") {
        *level = LOG_DEBUG;
    } else if (text == "info") {
        *level = LOG_INFO;
    } else if (text == "warn") {
        *level = LOG_WARN;
    } else if (text == "error") {
        *level = LOG_ERROR;
    } else {
        return false;
    }
    return true;
}

bool log_open_file(const std::string &path, std::string *error)
{
    FILE *file = fopen(path.c_str(), "a");

    if (file == NULL) {
        if (error != NULL) {
            *error = "impossible d'ouvrir le journal " + path + ": " + strerror(errno);

            // Piege courant: lancer le programme avec sudo en visant un fichier
            // deja cree par l'utilisateur ordinaire dans /tmp. Le noyau refuse,
            // car root ecrirait dans un fichier qui ne lui appartient pas, au
            // milieu d'un dossier ou tout le monde peut ecrire. C'est une
            // protection contre un piege classique, pas une panne.
            if (errno == EACCES || errno == EPERM) {
                *error += "\nSi vous lancez avec sudo, choisissez un chemin hors de /tmp,";
                *error += "\nou effacez d'abord le fichier existant.";
            }
        }
        return false;
    }

    log_close();
    g_stream = file;
    g_owns_stream = true;
    return true;
}

void log_close(void)
{
    if (g_owns_stream && g_stream != NULL)
        fclose(g_stream);
    g_stream = NULL;
    g_owns_stream = false;
}

static const char *level_name(LogLevel level)
{
    switch (level) {
    case LOG_DEBUG:
        return "DEBUG";
    case LOG_INFO:
        return "INFO";
    case LOG_WARN:
        return "WARN";
    case LOG_ERROR:
        return "ERROR";
    }
    return "?";
}

void log_write(LogLevel level, const char *format, ...)
{
    if (level < g_level)
        return;

    time_t now = time(NULL);
    struct tm broken;
    char stamp[32] = "";

    if (portable_localtime(&now, &broken))
        strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &broken);

    FILE *out = current_stream();
    fprintf(out, "%s [%-5s] ", stamp, level_name(level));
    va_list arguments;
    va_start(arguments, format);
    vfprintf(out, format, arguments);
    va_end(arguments);
    fputc('\n', out);
    fflush(out);
}
