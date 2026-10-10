#include "check.hpp"

#include "capture/interface.hpp"

// Ces tests interrogent la vraie machine. Ils ne verifient donc pas des noms
// precis, mais des proprietes vraies sur n'importe quelle machine Linux,
// FreeBSD ou macOS. Ils ne demandent aucun privilege.
void test_iface(void)
{
    printf("iface\n");

    std::string error;
    std::vector<Interface> list = list_interfaces(&error);

    CHECK(error.empty());
    // Toute machine possede au moins la boucle locale.
    CHECK(list.size() > 0);

    bool found_loopback = false;

    for (size_t i = 0; i < list.size(); i++) {
        CHECK(list[i].name.empty() == false);
        CHECK(list[i].index != 0);

        for (size_t j = 0; j < list[i].addresses.size(); j++) {
            int length = list[i].addresses[j].prefix_length;

            CHECK(length >= -1 && length <= 32);
        }

        if (list[i].is_loopback) {
            found_loopback = true;
            // La boucle locale ne doit jamais etre proposee pour capturer.
            CHECK(interface_is_capturable(list[i]) == false);
            // Elle s'appelle "lo" sur Linux, "lo0" sur FreeBSD et macOS.
            CHECK(list[i].name == "lo" || list[i].name == "lo0");
        }
    }

    CHECK(found_loopback == true);
}
