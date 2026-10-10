#pragma once

// Cet en-tete inclut volontairement de quoi ecrire un test sans y penser:
// printf, memcmp et std::string. C'est un choix assume pour les tests, pas
// une pratique a reprendre dans src/, ou chaque fichier inclut ce qu'il utilise.
#include <stdio.h>
#include <string.h>

#include <string>

// Petit outil de test maison.
//
// Pas besoin d'une bibliotheque de test pour ce projet: une macro qui compare
// et compte les echecs suffit, et elle tient en dix lignes qu'on peut lire.
//
// Chaque CHECK incremente un compteur. main.cpp affiche le bilan a la fin
// et renvoie 1 si au moins une verification a echoue, ce que CTest sait lire.

extern int tests_total;
extern int tests_failed;

void check(bool ok, const char *text, int line, const char *file);

#define CHECK(condition) check((condition), #condition, __LINE__, __FILE__)

// Chaque fichier de test expose sa fonction, appelee depuis main.cpp.
void test_bytes(void);
void test_mac(void);
void test_ipv4(void);
void test_iface(void);
void test_dissect(void);
void test_pcap(void);
void test_filter(void);
void test_analysis(void);
void test_log(void);
void test_color(void);
