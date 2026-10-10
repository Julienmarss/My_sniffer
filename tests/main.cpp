#include <stdio.h>

#include "check.hpp"

int tests_total = 0;
int tests_failed = 0;

void check(bool ok, const char *text, int line, const char *file)
{
    tests_total++;
    if (!ok) {
        printf("  ECHEC %s:%d  %s\n", file, line, text);
        tests_failed++;
    }
}

int main(void)
{
    test_bytes();
    test_mac();
    test_ipv4();
    test_iface();
    test_dissect();
    test_pcap();
    test_filter();
    test_analysis();
    test_log();
    test_color();

    printf("\n%d verifications, %d echec(s).\n", tests_total, tests_failed);
    if (tests_failed > 0)
        return 1;
    printf("Tout passe.\n");
    return 0;
}
