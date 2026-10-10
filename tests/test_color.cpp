#include "check.hpp"

#include <stdint.h>

#include "dissect/summary.hpp"
#include "term/color.hpp"

// La meme trame TCP que les tests du filtre. On la reutilise plutot que d'en
// recopier une troisieme.
extern const uint8_t *filter_test_tcp_frame(size_t *size);

// Retire d'un texte tous les codes de couleur, pour ne garder que ce que
// l'utilisateur voit reellement a l'ecran.
//
// Un code commence par l'octet d'echappement 27 suivi de '[', et se termine
// au premier 'm'. C'est la seule forme qu'on produit.
static std::string visible_text(const std::string &text)
{
    std::string out;
    size_t i = 0;

    while (i < text.size()) {
        if (text[i] == '\033' && i + 1 < text.size() && text[i + 1] == '[') {
            while (i < text.size() && text[i] != 'm')
                i++;
            if (i < text.size())
                i++;  // on saute aussi le 'm'
            continue;
        }
        out += text[i];
        i++;
    }
    return out;
}

void test_color(void)
{
    printf("color\n");

    // ------------------------------------------------------ le remplissage
    CHECK(pad_right("abc", 6) == "abc   ");
    CHECK(pad_right("abc", 3) == "abc");
    // Un texte trop long n'est jamais coupe: une adresse tronquee serait un
    // mensonge, une ligne qui depasse n'est qu'une ligne qui depasse.
    CHECK(pad_right("abcdef", 3) == "abcdef");
    CHECK(pad_right("", 2) == "  ");

    // ------------------------------------------------------------- palette
    Palette none = choose_palette(COLOR_NEVER);

    CHECK(none.address[0] == '\0');
    CHECK(none.alert[0] == '\0');
    CHECK(none.reset[0] == '\0');

    // Une palette construite sans rien dire n'a aucune couleur non plus.
    // C'est ce qui fait qu'un SummaryOptions par defaut sort du texte brut.
    Palette fresh;

    CHECK(fresh.dim[0] == '\0');
    CHECK(fresh.protocol[0] == '\0');

    Palette colors = choose_palette(COLOR_ALWAYS);

    CHECK(colors.address[0] == '\033');
    CHECK(std::string(colors.reset) == "\033[0m");

    // --------------------------------------------------------- la peinture
    // Sans couleur, le texte ressort a l'identique: c'est ce qui garantit
    // qu'on peut rediriger la sortie sans rien salir.
    CHECK(paint(none, none.address, "abc") == "abc");
    CHECK(paint(colors, colors.address, "abc") == "\033[36mabc\033[0m");

    // ------------------------------------------------------- lecture du mot
    ColorChoice choice = COLOR_AUTO;

    CHECK(color_choice_from_string("never", &choice) == true);
    CHECK(choice == COLOR_NEVER);
    CHECK(color_choice_from_string("always", &choice) == true);
    CHECK(choice == COLOR_ALWAYS);
    CHECK(color_choice_from_string("auto", &choice) == true);
    CHECK(choice == COLOR_AUTO);
    // Une faute de frappe doit se voir, pas passer pour un reglage valide.
    CHECK(color_choice_from_string("bleu", &choice) == false);
    CHECK(color_choice_from_string("", &choice) == false);
    CHECK(choice == COLOR_AUTO);

    // ----------------------------------------- le point qui compte vraiment
    // La couleur ne doit RIEN changer au contenu: une fois les codes retires,
    // la ligne coloree doit etre exactement la ligne en texte brut. Sinon on
    // afficherait deux choses differentes selon qu'on regarde l'ecran ou un
    // fichier, et on ne pourrait plus se fier a ce qu'on lit.
    size_t size = 0;
    const uint8_t *frame = filter_test_tcp_frame(&size);
    DecodedPacket packet = decode_packet(frame, size);

    SummaryOptions plain;
    SummaryOptions painted;

    painted.palette = colors;

    std::string plain_line = summarize_packet(packet, 0, 0, plain).line;
    std::string painted_line = summarize_packet(packet, 0, 0, painted).line;

    CHECK(painted_line != plain_line);
    CHECK(visible_text(painted_line) == plain_line);

    // Et la verification reste vraie quelle que soit la facon dont le paquet
    // est coupe, y compris sur les chemins d'erreur.
    //
    // Un seul CHECK pour toute la boucle: un CHECK a l'interieur compterait
    // des centaines de verifications pour une seule idee, et le total des
    // tests ne voudrait plus rien dire.
    bool always_identical = true;

    for (size_t cut = 0; cut <= size; cut++) {
        DecodedPacket piece = decode_packet(frame, cut);
        std::string bare = summarize_packet(piece, 0, 0, plain).line;
        std::string colored = summarize_packet(piece, 0, 0, painted).line;

        if (visible_text(colored) != bare)
            always_identical = false;
    }
    CHECK(always_identical);
}
