#include "check.hpp"

#include <stdio.h>
#include <unistd.h>

#include "log/log.hpp"

// Relit un fichier entier.
static std::string read_file(const char *path)
{
    FILE *file = fopen(path, "rb");

    if (file == NULL)
        return std::string();

    std::string text;
    char buffer[512];
    size_t read = 0;

    while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0)
        text.append(buffer, read);
    fclose(file);
    return text;
}

void test_log(void)
{
    printf("log\n");

    const char *path = "/tmp/mysniffer_test_log.txt";

    unlink(path);

    std::string error;

    CHECK(log_open_file(path, &error) == true);
    CHECK(error.empty() == true);

    // Au niveau warn, les messages moins graves sont jetes.
    log_set_level(LOG_WARN);
    log_write(LOG_DEBUG, "ceci ne doit pas apparaitre");
    log_write(LOG_INFO, "ceci non plus");
    log_write(LOG_WARN, "ceci oui, %d fois", 1);
    log_write(LOG_ERROR, "ceci aussi");

    std::string text = read_file(path);

    CHECK(text.find("ne doit pas apparaitre") == std::string::npos);
    CHECK(text.find("non plus") == std::string::npos);
    CHECK(text.find("ceci oui, 1 fois") != std::string::npos);
    CHECK(text.find("ceci aussi") != std::string::npos);
    CHECK(text.find("[WARN ]") != std::string::npos);
    CHECK(text.find("[ERROR]") != std::string::npos);

    // En descendant le niveau, tout passe.
    log_set_level(LOG_DEBUG);
    log_write(LOG_DEBUG, "maintenant visible");
    text = read_file(path);
    CHECK(text.find("maintenant visible") != std::string::npos);

    // Le fichier est ouvert en ajout: ce qui precede doit survivre.
    CHECK(text.find("ceci aussi") != std::string::npos);

    log_close();
    unlink(path);

    // Les niveaux se lisent en toutes lettres.
    LogLevel level = LOG_WARN;

    CHECK(log_level_from_string("debug", &level) == true);
    CHECK(level == LOG_DEBUG);
    CHECK(log_level_from_string("info", &level) == true);
    CHECK(level == LOG_INFO);
    CHECK(log_level_from_string("warn", &level) == true);
    CHECK(level == LOG_WARN);
    CHECK(log_level_from_string("error", &level) == true);
    CHECK(level == LOG_ERROR);
    CHECK(log_level_from_string("nimportequoi", &level) == false);
    CHECK(log_level_from_string("", &level) == false);

    // Un fichier qu'on ne peut pas creer doit echouer proprement.
    CHECK(log_open_file("/nexiste/pas/journal.txt", &error) == false);
    CHECK(error.empty() == false);

    // Fermer sans avoir ouvert ne doit rien casser.
    log_close();
    log_close();

    // On remet le niveau par defaut pour ne pas polluer les autres tests.
    log_set_level(LOG_WARN);
}
