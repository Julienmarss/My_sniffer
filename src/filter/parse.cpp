// Transforme le texte d'une regle en arbre.
//
// Le travail se fait en deux temps, comme dans tous les analyseurs:
//
//   1. On decoupe le texte en mots. "tcp and port 80" devient
//      ["tcp", "and", "port", "80"]. Les parentheses comptent pour un mot
//      meme collees au reste.
//
//   2. On lit ces mots de gauche a droite en construisant l'arbre. Chaque
//      niveau de priorite a sa fonction: le OU appelle le ET, qui appelle le
//      NON, qui appelle les tests elementaires. C'est ce qui fait que
//      "a or b and c" se comprend comme "a or (b and c)", et non l'inverse.

#include "filter/filter.hpp"


#include <string>
#include <vector>

// ------------------------------------------------------- decoupage en mots

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static std::vector<std::string> split_words(const std::string &text)
{
    std::vector<std::string> words;
    std::string current;

    for (size_t i = 0; i < text.size(); i++) {
        char c = text[i];

        if (is_space(c) || c == '(' || c == ')') {
            if (!current.empty()) {
                words.push_back(current);
                current.clear();
            }
            // Les parentheses sont des mots a elles seules.
            if (c == '(' || c == ')')
                words.push_back(std::string(1, c));
            continue;
        }
        current += c;
    }
    if (!current.empty())
        words.push_back(current);
    return words;
}

// ------------------------------------------------- etat de l'analyse en cours

// Deux garde-fous contre une regle ecrite expres pour faire tomber le
// programme. Une vraie regle ne s'en approche jamais: elle tient en une ligne.
//
// MAX_DEPTH borne l'imbrication. Chaque parenthese ouvrante et chaque "not"
// font descendre l'analyseur d'un cran, et un cran coute de la pile. Sans
// limite, "((((((...tcp...))))))" repete quelques dizaines de milliers de fois
// epuise la pile et le programme meurt en plein vol.
//
// MAX_TERMS borne le nombre de conditions enchainees par "and" ou "or".
// Ces conditions forment un arbre penche a gauche, aussi profond qu'il y a de
// termes, et c'est l'EVALUATION qui descend dedans, a chaque paquet. Une regle
// de 200000 "and" s'analyserait sans probleme et ne planterait qu'au premier
// paquet, ce qui serait bien plus difficile a comprendre.
static const int MAX_DEPTH = 64;
static const int MAX_TERMS = 256;

// Tout ce dont l'analyse a besoin: les mots, ou on en est, l'arbre en
// construction, la profondeur actuelle, et le message d'erreur eventuel.
struct Parser {
    std::vector<std::string> words;
    size_t position;
    Filter *filter;
    int depth;
    std::string error;
};

static bool at_end(const Parser &parser)
{
    return parser.position >= parser.words.size();
}

// Le mot courant, ou une chaine vide si on est au bout.
static std::string current_word(const Parser &parser)
{
    if (at_end(parser))
        return std::string();
    return parser.words[parser.position];
}

// Vrai si le mot courant est celui-la. Ne consomme rien.
static bool looking_at(const Parser &parser, const char *word)
{
    return current_word(parser) == word;
}

// Consomme le mot courant s'il correspond, et dit si c'etait le cas.
static bool accept(Parser *parser, const char *word)
{
    if (!looking_at(*parser, word))
        return false;
    parser->position++;
    return true;
}

static bool fail(Parser *parser, const std::string &message)
{
    if (parser->error.empty()) {
        parser->error = message;
        if (!at_end(*parser))
            parser->error += " (a '" + current_word(*parser) + "')";
        else
            parser->error += " (fin de la regle)";
    }
    return false;
}

// Ajoute un noeud a l'arbre et rend sa position.
static int add_node(Parser *parser, FilterKind kind)
{
    FilterNode node = {};

    node.kind = kind;
    node.left = -1;
    node.right = -1;
    node.direction = DIRECTION_ANY;

    parser->filter->nodes.push_back(node);
    return static_cast<int>(parser->filter->nodes.size()) - 1;
}

// ------------------------------------------------------- tests elementaires

// Lit un nombre ecrit en chiffres, et rien d'autre.
//
// On n'utilise surtout pas atoi() ici. atoi() rend zero aussi bien pour "0"
// que pour "abc", donc une faute de frappe passerait pour un zero valide.
// Ecrite "/abc", une regle de reseau deviendrait "/0" et garderait tout le
// trafic, en silence. Mieux vaut refuser franchement.
static bool decimal_value(const std::string &text, uint32_t maximum, uint32_t *out)
{
    if (text.empty())
        return false;

    uint32_t value = 0;

    for (size_t i = 0; i < text.size(); i++) {
        if (text[i] < '0' || text[i] > '9')
            return false;
        value = value * 10 + static_cast<uint32_t>(text[i] - '0');
        if (value > maximum)
            return false;
    }

    *out = value;
    return true;
}

// Lit le mot courant comme un nombre, et avance si c'en est un.
static bool read_number(Parser *parser, uint32_t maximum, uint32_t *out)
{
    std::string word = current_word(*parser);

    if (word.empty())
        return fail(parser, "un nombre est attendu");
    if (!decimal_value(word, maximum, out)) {
        return fail(parser, "'" + word + "' n'est pas un nombre valide (maximum "
                            + std::to_string(maximum) + ")");
    }

    parser->position++;
    return true;
}

// Reconnait un nom de protocole. Rend -1 si ce mot n'en est pas un.
static int protocol_from_word(const std::string &word)
{
    if (word == "eth" || word == "ether")
        return PROTOCOL_ETHERNET;
    if (word == "arp")
        return PROTOCOL_ARP;
    if (word == "vlan")
        return PROTOCOL_VLAN;
    if (word == "ip" || word == "ipv4")
        return PROTOCOL_IPV4;
    if (word == "ip6" || word == "ipv6")
        return PROTOCOL_IPV6;
    if (word == "tcp")
        return PROTOCOL_TCP;
    if (word == "udp")
        return PROTOCOL_UDP;
    if (word == "icmp")
        return PROTOCOL_ICMP;
    return -1;
}

// "syn", "ack", "syn,ack"... rend le masque correspondant, ou -1 si un nom
// n'est pas reconnu.
static int flags_from_word(const std::string &word)
{
    int mask = 0;
    std::string name;

    // On ajoute une virgule a la fin pour traiter le dernier nom comme les autres.
    std::string list = word + ",";

    for (size_t i = 0; i < list.size(); i++) {
        if (list[i] != ',') {
            name += list[i];
            continue;
        }
        if (name == "fin")       mask |= 0x01;
        else if (name == "syn")  mask |= 0x02;
        else if (name == "rst")  mask |= 0x04;
        else if (name == "psh")  mask |= 0x08;
        else if (name == "ack")  mask |= 0x10;
        else if (name == "urg")  mask |= 0x20;
        else if (name == "ece")  mask |= 0x40;
        else if (name == "cwr")  mask |= 0x80;
        else return -1;
        name.clear();
    }
    return mask;
}

// "host X", "net X/N", "port N", "portrange A-B", precedes ou non d'une
// direction. Rend la position du noeud cree, ou -1 en cas d'erreur.
static int parse_address_or_port(Parser *parser, FilterDirection direction)
{
    if (accept(parser, "host")) {
        int index = add_node(parser, FILTER_HOST);
        std::string word = current_word(*parser);

        if (!ipv4_from_string(word, &parser->filter->nodes[static_cast<size_t>(index)].address)) {
            fail(parser, "'" + word + "' n'est pas une adresse IPv4");
            return -1;
        }
        parser->position++;
        parser->filter->nodes[static_cast<size_t>(index)].direction = direction;
        return index;
    }

    if (accept(parser, "net")) {
        std::string word = current_word(*parser);
        size_t slash = word.find('/');
        std::string address_part = (slash == std::string::npos) ? word : word.substr(0, slash);
        Ipv4 address;

        if (!ipv4_from_string(address_part, &address)) {
            fail(parser, "'" + word + "' n'est pas un reseau valide");
            return -1;
        }

        // Sans "/N", on prend /32, c'est-a-dire une seule machine.
        int length = 32;

        if (slash != std::string::npos) {
            std::string number = word.substr(slash + 1);
            uint32_t bits = 0;

            if (!decimal_value(number, 32, &bits)) {
                fail(parser, "apres le '/', on attend un nombre de bits de 0 a 32");
                return -1;
            }
            length = static_cast<int>(bits);
        }

        parser->position++;

        int index = add_node(parser, FILTER_NET);
        FilterNode &node = parser->filter->nodes[static_cast<size_t>(index)];

        node.address = address;
        node.prefix_length = length;
        node.direction = direction;
        return index;
    }

    if (accept(parser, "port")) {
        uint32_t port = 0;

        if (!read_number(parser, 65535, &port))
            return -1;

        int index = add_node(parser, FILTER_PORT);
        FilterNode &node = parser->filter->nodes[static_cast<size_t>(index)];

        node.port_low = static_cast<uint16_t>(port);
        node.direction = direction;
        return index;
    }

    if (accept(parser, "portrange")) {
        std::string word = current_word(*parser);
        size_t dash = word.find('-');

        if (dash == std::string::npos) {
            fail(parser, "portrange attend deux ports separes par un tiret");
            return -1;
        }

        uint32_t low = 0;
        uint32_t high = 0;

        if (!decimal_value(word.substr(0, dash), 65535, &low)
            || !decimal_value(word.substr(dash + 1), 65535, &high)) {
            fail(parser, "portrange attend deux nombres de 0 a 65535, par exemple 80-443");
            return -1;
        }
        if (low > high) {
            fail(parser, "le premier port doit etre le plus petit");
            return -1;
        }
        parser->position++;

        int index = add_node(parser, FILTER_PORT_RANGE);
        FilterNode &node = parser->filter->nodes[static_cast<size_t>(index)];

        node.port_low = static_cast<uint16_t>(low);
        node.port_high = static_cast<uint16_t>(high);
        node.direction = direction;
        return index;
    }

    if (direction != DIRECTION_ANY) {
        fail(parser, "apres 'src' ou 'dst', on attend host, net, port ou portrange");
        return -1;
    }
    return -1;
}

// Ces trois fonctions s'appellent entre elles: le OU appelle le ET, qui
// appelle le test elementaire, qui peut rouvrir une parenthese et donc
// revenir au OU. On les annonce donc avant de les ecrire.
static int parse_or(Parser *parser);
static int parse_and(Parser *parser);
static int parse_primary(Parser *parser);

// Un test elementaire: un protocole, une adresse, un port, des drapeaux,
// une longueur, ou une expression entre parentheses.
static int parse_predicate(Parser *parser)
{
    // Une direction annonce forcement host, net, port ou portrange.
    if (accept(parser, "src"))
        return parse_address_or_port(parser, DIRECTION_SOURCE);
    if (accept(parser, "dst"))
        return parse_address_or_port(parser, DIRECTION_DESTINATION);

    int index = parse_address_or_port(parser, DIRECTION_ANY);

    if (index >= 0 || !parser->error.empty())
        return index;

    if (accept(parser, "tcp-flags")) {
        int mask = flags_from_word(current_word(*parser));

        if (mask < 0) {
            fail(parser, "drapeau TCP inconnu: '" + current_word(*parser) + "'");
            return -1;
        }
        parser->position++;

        int node_index = add_node(parser, FILTER_TCP_FLAGS);

        parser->filter->nodes[static_cast<size_t>(node_index)].flags_mask =
            static_cast<uint8_t>(mask);
        return node_index;
    }

    if (accept(parser, "len")) {
        std::string comparison = current_word(*parser);
        FilterComparison kind = COMPARE_EQUAL;

        if (comparison == "<") {
            kind = COMPARE_LESS;
        } else if (comparison == "<=") {
            kind = COMPARE_LESS_OR_EQUAL;
        } else if (comparison == ">") {
            kind = COMPARE_GREATER;
        } else if (comparison == ">=") {
            kind = COMPARE_GREATER_OR_EQUAL;
        } else if (comparison == "=" || comparison == "==") {
            kind = COMPARE_EQUAL;
        } else if (comparison == "!=") {
            kind = COMPARE_NOT_EQUAL;
        } else {
            fail(parser, "len attend une comparaison: <, <=, >, >=, = ou !=");
            return -1;
        }
        parser->position++;

        uint32_t value = 0;

        if (!read_number(parser, 65535, &value))
            return -1;

        int node_index = add_node(parser, FILTER_LENGTH);
        FilterNode &node = parser->filter->nodes[static_cast<size_t>(node_index)];

        node.comparison = kind;
        node.value = value;
        return node_index;
    }

    int protocol = protocol_from_word(current_word(*parser));

    if (protocol >= 0) {
        parser->position++;

        int node_index = add_node(parser, FILTER_PROTOCOL);

        parser->filter->nodes[static_cast<size_t>(node_index)].protocol =
            static_cast<FilterProtocol>(protocol);
        return node_index;
    }

    fail(parser, "mot inconnu");
            return -1;
}

// Descend d'un cran. Refuse si la regle est deja trop imbriquee.
static bool go_deeper(Parser *parser)
{
    if (parser->depth >= MAX_DEPTH) {
        fail(parser, "regle trop imbriquee (maximum "
                     + std::to_string(MAX_DEPTH) + " niveaux)");
        return false;
    }
    parser->depth++;
    return true;
}

// Un test, eventuellement precede de "not", ou une expression entre parentheses.
static int parse_primary(Parser *parser)
{
    if (accept(parser, "not") || accept(parser, "!")) {
        if (!go_deeper(parser))
            return -1;

        int child = parse_primary(parser);

        parser->depth--;
        if (child < 0)
            return -1;

        int index = add_node(parser, FILTER_NOT);

        parser->filter->nodes[static_cast<size_t>(index)].left = child;
        return index;
    }

    if (accept(parser, "(")) {
        if (!go_deeper(parser))
            return -1;

        int inside = parse_or(parser);

        parser->depth--;
        if (inside < 0)
            return -1;
        if (!accept(parser, ")")) {
            fail(parser, "parenthese fermante manquante");
            return -1;
        }
        return inside;
    }

    return parse_predicate(parser);
}

// Les "and" se lient plus fort que les "or", d'ou deux niveaux.
static int parse_and(Parser *parser)
{
    int left = parse_primary(parser);

    if (left < 0)
        return -1;

    int terms = 1;

    while (accept(parser, "and") || accept(parser, "&&")) {
        if (++terms > MAX_TERMS) {
            fail(parser, "trop de conditions enchainees (maximum "
                         + std::to_string(MAX_TERMS) + ")");
            return -1;
        }

        int right = parse_primary(parser);

        if (right < 0)
            return -1;

        int index = add_node(parser, FILTER_AND);
        FilterNode &node = parser->filter->nodes[static_cast<size_t>(index)];

        node.left = left;
        node.right = right;
        left = index;
    }
    return left;
}

static int parse_or(Parser *parser)
{
    int left = parse_and(parser);

    if (left < 0)
        return -1;

    int terms = 1;

    while (accept(parser, "or") || accept(parser, "||")) {
        if (++terms > MAX_TERMS) {
            fail(parser, "trop de conditions enchainees (maximum "
                         + std::to_string(MAX_TERMS) + ")");
            return -1;
        }

        int right = parse_and(parser);

        if (right < 0)
            return -1;

        int index = add_node(parser, FILTER_OR);
        FilterNode &node = parser->filter->nodes[static_cast<size_t>(index)];

        node.left = left;
        node.right = right;
        left = index;
    }
    return left;
}

bool filter_parse(const std::string &text, Filter *filter, std::string *error)
{
    *filter = filter_accept_all();

    Parser parser;

    parser.words = split_words(text);
    parser.position = 0;
    parser.filter = filter;
    parser.depth = 0;

    // Une regle vide laisse tout passer, ce n'est pas une erreur.
    if (parser.words.empty())
        return true;

    int root = parse_or(&parser);

    if (root < 0) {
        if (error != NULL)
            *error = parser.error;
        *filter = filter_accept_all();
        return false;
    }

    // Tous les mots doivent avoir ete consommes: s'il en reste, la regle est
    // mal formee, par exemple "tcp port" ou "tcp 80".
    if (!at_end(parser)) {
        if (error != NULL)
            *error = "mot en trop: '" + current_word(parser) + "'";
        *filter = filter_accept_all();
        return false;
    }

    filter->root = root;
    return true;
}
