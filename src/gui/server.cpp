// Petit serveur web local pour piloter mysniffer depuis un navigateur.
//
// Bonus du sujet ("A GUI and/or TUI on top of your sniffer"). Ce fichier
// n'est compile que sous Linux (voir CMakeLists.txt): c'est un outil de
// demonstration pour cette machine, pas un livrable multiplateforme comme
// le reste du projet.
//
// Les sockets utilisees ici servent un serveur HTTP ordinaire, sans rapport
// avec la capture de paquets: le sujet interdit les bibliotheques de
// capture et de decodage de protocole, pas les sockets applicatives d'un
// outil qui n'a rien a voir avec le sniffer lui-meme. Comme ailleurs dans
// le projet, l'ordre des octets reseau est recompose a la main plutot que
// d'appeler htons (voir capture_linux.cpp): coherence avec le reste du code.
//
// Principe: une page HTML avec des boutons. Chaque bouton envoie un nom
// d'action fixe ("capture", "analyze"...). Le serveur associe ce nom a une
// commande ecrite a l'avance dans ACTIONS: la ligne de commande n'est
// JAMAIS construite a partir de ce que le navigateur envoie, pour qu'il n'y
// ait rien a injecter.

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

namespace {

const int PORT = 7878;

// Meme principe que to_network_order() dans capture_linux.cpp: le sujet
// interdit htons, qui vient de <arpa/inet.h>, donc on refait l'equivalent.
uint16_t to_network_order(uint16_t value)
{
    uint16_t result = 0;
    uint8_t *bytes = reinterpret_cast<uint8_t *>(&result);

    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value & 0xff);
    return result;
}

// Une trame ARP, une ICMP et une TCP, deja enregistrees au format pcap.
// Le bouton "bonus protocoles" relit ce fichier plutot que d'esperer qu'une
// vraie trame ARP ou ICMP passe au bon moment pendant la soutenance.
const unsigned char DEMO_PCAP[] = {
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x78, 0xe7, 0x68, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
    0x2a, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc8, 0x5e,
    0xa9, 0x53, 0x40, 0x3a, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
    0x00, 0x01, 0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0xc0, 0xa8, 0x01, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x01, 0x78,
    0xe7, 0x68, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x2e, 0x00,
    0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22, 0xee, 0xff, 0xc8, 0x5e, 0xa9, 0x53,
    0x40, 0x30, 0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x1c, 0x46, 0x40, 0x00,
    0x40, 0x01, 0x4c, 0xd5, 0xc0, 0xa8, 0x01, 0x0a, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x00, 0x21, 0x04, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64,
    0x02, 0x78, 0xe7, 0x68, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
    0x36, 0x00, 0x00, 0x00, 0xc8, 0x5e, 0xa9, 0x53, 0x40, 0x3a, 0x00, 0x1a,
    0x2b, 0x3c, 0x4d, 0x5e, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x1c, 0x46,
    0x40, 0x00, 0x40, 0x06, 0x26, 0xfd, 0xc0, 0xa8, 0x01, 0x0a, 0x5d, 0xb8,
    0xd8, 0x22, 0xd4, 0x31, 0x00, 0x50, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x02, 0xfa, 0xf0, 0x80, 0x36, 0x00, 0x00
};

// La commande associee a chaque bouton. "%BIN%" et "%TMP%" sont remplaces
// avant l'execution par le chemin de mysniffer et par un dossier prive cree
// au lancement (voir run_action() et make_private_tmp_dir()): jamais le
// /tmp partage par tout le monde, pour ne pas pouvoir y etre piege par un
// lien symbolique depose a l'avance par un autre utilisateur.
struct Action {
    const char *key;
    const char *command;
};

const Action ACTIONS[] = {
    {"version", "%BIN% --version"},
    {"interfaces", "%BIN% interfaces --all"},
    {"capture", "%BIN% capture -c 5 --color never"},
    {"filter", "%BIN% capture -c 5 -f \"tcp and port 443\" --color never"},
    // Le reseau n'offre pas toujours de l'UDP au moment pile ou on capture.
    // On en declenche nous-memes avec de vraies requetes DNS (un sous-domaine
    // invente a chaque fois, pour ne jamais retomber sur un resultat deja en
    // cache) pendant que la capture, filtree sur udp, tourne deja en
    // arriere-plan. ".invalid" est evite expres: certains systemes le
    // reconnaissent et repondent sans meme interroger le reseau.
    {"udp",
     "%BIN% capture -c 3 -f udp --color never & "
     "CAPTURE_PID=$!; "
     "sleep 0.3; "
     "getent hosts \"demo1-$(date +%s%N).wikipedia.org\" >/dev/null 2>&1; "
     "getent hosts \"demo2-$(date +%s%N).github.com\" >/dev/null 2>&1; "
     "getent hosts \"demo3-$(date +%s%N).mozilla.org\" >/dev/null 2>&1; "
     "wait $CAPTURE_PID"},
    {"pcap",
     "%BIN% capture -c 10 -w %TMP%/capture.pcap --color never "
     ">%TMP%/write.log 2>&1; "
     "echo '--- ecriture terminee, relecture du fichier ---'; "
     "%BIN% read -r %TMP%/capture.pcap --color never"},
    {"analyze",
     "%BIN% capture -c 30 -w %TMP%/analyze.pcap --color never "
     ">/dev/null 2>&1; "
     "%BIN% analyze -r %TMP%/analyze.pcap --color never"},
    {"bonus", "%BIN% read -r %TMP%/demo.pcap --color never"},
};
const size_t ACTION_COUNT = sizeof(ACTIONS) / sizeof(ACTIONS[0]);

// La page entiere: structure, style et script, pour n'avoir qu'un seul
// fichier a lancer. "mysniffer" tourne sans base de donnees ni serveur web
// habituel: pas la peine d'en ajouter un pour cette seule page.
const char *PAGE = R"HTML(<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>My_sniffer</title>
<style>
  body { background: #11161c; color: #d6dde5; font-family: monospace;
         margin: 0; padding: 24px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  p.sub { color: #7f8a96; margin: 0 0 20px; font-size: 13px; }
  .buttons { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }
  button { background: #1b2430; color: #d6dde5; border: 1px solid #2d3a4a;
           border-radius: 6px; padding: 10px 16px; font-family: monospace;
           font-size: 14px; cursor: pointer; }
  button:hover { background: #24303f; }
  button:disabled { opacity: 0.5; cursor: default; }
  pre { background: #0b0f14; border: 1px solid #2d3a4a; border-radius: 6px;
        padding: 14px; min-height: 300px; white-space: pre-wrap;
        word-break: break-word; font-size: 13px; line-height: 1.4; }
</style>
</head>
<body>
  <h1>My_sniffer</h1>
  <p class="sub">Chaque bouton lance une vraie commande sur cette machine
     et affiche son resultat tel quel, ci-dessous.</p>
  <div class="buttons">
    <button data-action="version">Version</button>
    <button data-action="interfaces">Interfaces reseau</button>
    <button data-action="capture">Capture live (5 paquets)</button>
    <button data-action="filter">Filtre (HTTPS uniquement)</button>
    <button data-action="udp">UDP (requetes DNS declenchees)</button>
    <button data-action="pcap">Ecrire + relire un .pcap</button>
    <button data-action="analyze">Analyse comportementale</button>
    <button data-action="bonus">Bonus: ARP + ICMP</button>
  </div>
  <pre id="output">Resultat ici.</pre>
<script>
// Jeton tire au hasard a chaque lancement du serveur (voir generate_token()
// cote C++): sans lui, une page malveillante ouverte dans un autre onglet
// ne peut pas se faire passer pour un clic sur un de ces boutons.
var TOKEN = '%TOKEN%';
var output = document.getElementById('output');
var buttons = document.querySelectorAll('button');

buttons.forEach(function (button) {
  button.addEventListener('click', function () {
    var action = button.getAttribute('data-action');

    buttons.forEach(function (b) { b.disabled = true; });
    output.textContent = 'Lancement de "' + action + '"...';

    fetch('/run?action=' + action + '&token=' + TOKEN)
      .then(function (response) { return response.text(); })
      .then(function (text) { output.textContent = text; })
      .catch(function (error) { output.textContent = 'Erreur: ' + error; })
      .finally(function () {
        buttons.forEach(function (b) { b.disabled = false; });
      });
  });
});
</script>
</body>
</html>
)HTML";

// Ou se trouve ce programme, pour retrouver mysniffer juste a cote sans
// dependre du dossier depuis lequel on l'a lance.
std::string binary_directory(void)
{
    char buffer[4096];
    ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);

    if (length <= 0)
        return ".";
    buffer[length] = '\0';

    std::string path(buffer);
    size_t slash = path.find_last_of('/');

    return (slash == std::string::npos) ? "." : path.substr(0, slash);
}

// Un jeton different a chaque lancement, impossible a deviner de l'exterieur.
// C'est lui qui empeche une page ouverte dans un autre onglet de declencher
// une capture a notre insu: elle ne peut pas le connaitre.
std::string generate_token(void)
{
    unsigned char raw[16];
    FILE *urandom = fopen("/dev/urandom", "rb");

    if (urandom != NULL) {
        size_t got = fread(raw, 1, sizeof(raw), urandom);

        fclose(urandom);
        if (got == sizeof(raw)) {
            char hex[sizeof(raw) * 2 + 1];

            for (size_t i = 0; i < sizeof(raw); i++)
                snprintf(hex + i * 2, 3, "%02x", raw[i]);
            return std::string(hex, sizeof(raw) * 2);
        }
    }

    // /dev/urandom absent: cas quasi impossible sous Linux, mais on ne doit
    // jamais rendre un jeton vide ou constant. L'heure et le PID suffisent
    // a eviter ca, meme si c'est moins fort qu'un vrai tirage aleatoire.
    char fallback[32];

    snprintf(fallback, sizeof(fallback), "%lx%lx",
             static_cast<unsigned long>(time(NULL)), static_cast<unsigned long>(getpid()));
    return std::string(fallback);
}

// Un dossier prive (droits 0700), cree juste pour cette execution, plutot
// que des chemins fixes dans /tmp. Un /tmp partage entre tous les
// utilisateurs permet a n'importe qui d'y deposer a l'avance un lien
// symbolique au nom attendu: le programme, lance en root pour la capture,
// ecrirait alors a travers ce lien n'importe ou sur le disque. Un dossier
// prive, cree au dernier moment avec un nom impredictible, ferme cette porte.
std::string make_private_tmp_dir(void)
{
    char tpl[] = "/tmp/mysniffer_gui_XXXXXX";
    char *dir = mkdtemp(tpl);

    if (dir == NULL) {
        fprintf(stderr, "erreur: impossible de creer un dossier temporaire\n");
        exit(1);
    }
    return std::string(dir);
}

std::string replace_all(std::string text, const std::string &from, const std::string &to)
{
    size_t position = 0;

    while ((position = text.find(from, position)) != std::string::npos) {
        text.replace(position, from.size(), to);
        position += to.size();
    }
    return text;
}

// Lance une commande deja entierement ecrite (jamais assemblee a partir de
// ce que le navigateur a envoye) et rend ce qu'elle a affiche.
std::string run_shell(const std::string &command)
{
    FILE *pipe = popen(command.c_str(), "r");

    if (pipe == NULL)
        return "erreur: impossible de lancer la commande";

    std::string output;
    char buffer[4096];
    size_t got;

    while ((got = fread(buffer, 1, sizeof(buffer), pipe)) > 0)
        output.append(buffer, got);
    pclose(pipe);
    return output;
}

std::string run_action(const std::string &key, const std::string &bin_dir,
                       const std::string &tmp_dir)
{
    for (size_t i = 0; i < ACTION_COUNT; i++) {
        if (key != ACTIONS[i].key)
            continue;
        std::string command = replace_all(ACTIONS[i].command, "%BIN%", bin_dir + "/mysniffer");

        command = replace_all(command, "%TMP%", tmp_dir);
        // mysniffer ecrit ses erreurs et son journal sur la sortie d'erreur,
        // volontairement separee du resultat (voir docs/USAGE.md). Sans ce
        // "2>&1", un echec de privileges afficherait une page vide au lieu
        // du message qui explique pourquoi.
        return run_shell("(" + command + ") 2>&1");
    }
    return "action inconnue: " + key;
}

// Extrait la valeur de "nom=X" dans la ligne de requete HTTP, par exemple
// "action" ou "token" dans "GET /run?action=capture&token=abcd HTTP/1.1".
std::string extract_param(const std::string &request_line, const std::string &name)
{
    size_t marker = request_line.find(name + "=");

    if (marker == std::string::npos)
        return "";

    size_t start = marker + name.size() + 1;
    size_t end = request_line.find_first_of(" &", start);

    return request_line.substr(start, end - start);
}

// Extrait l'en-tete "Host:" de la requete, en minuscules.
//
// Un jeton correct ne suffit pas a lui seul: une page attaquante peut faire
// pointer son propre nom de domaine vers 127.0.0.1 apres coup ("DNS
// rebinding"), auquel cas le navigateur la considere comme venant de ce
// serveur et la laisse lire la reponse, jeton compris. L'en-tete Host, lui,
// garde le nom demande par le navigateur, pas l'adresse IP jointe: le
// comparer a ce qu'on attend dejoue ce detour.
std::string extract_host(const std::string &request)
{
    size_t marker = request.find("\r\nHost:");

    if (marker == std::string::npos)
        return "";

    size_t start = marker + 7;
    size_t end = request.find("\r\n", start);
    std::string host = request.substr(start, end - start);

    // Retire les espaces autour, et met en minuscules: "Host:" les accepte
    // dans les deux cas, nous non pour rester simples.
    while (!host.empty() && host.front() == ' ')
        host.erase(host.begin());
    for (size_t i = 0; i < host.size(); i++)
        host[i] = static_cast<char>(tolower(static_cast<unsigned char>(host[i])));
    return host;
}

bool host_is_allowed(const std::string &host)
{
    return host == "127.0.0.1:7878" || host == "localhost:7878";
}

void write_all(int socket_fd, const std::string &data)
{
    size_t sent = 0;

    while (sent < data.size()) {
        ssize_t n = write(socket_fd, data.data() + sent, data.size() - sent);

        if (n <= 0)
            return;
        sent += static_cast<size_t>(n);
    }
}

void send_response(int client, const std::string &content_type, const std::string &body)
{
    std::string header = "HTTP/1.1 200 OK\r\nContent-Type: " + content_type
                        + "\r\nContent-Length: " + std::to_string(body.size())
                        + "\r\nConnection: close\r\n\r\n";

    write_all(client, header);
    write_all(client, body);
}

// Ecrit le fichier de demonstration une fois pour toutes, pour que le
// bouton "bonus" marche meme sans trafic ARP ou ICMP reel sur le reseau.
//
// O_EXCL refuse d'ecrire si le fichier existe deja (donc aussi s'il s'agit
// d'un lien symbolique pose a l'avance), et O_NOFOLLOW refuse de le suivre
// meme sans O_EXCL: deux gardes-fous independants pour la meme regle que
// make_private_tmp_dir(), au cas ou quelqu'un reutiliserait ce chemin seul.
void write_demo_pcap(const std::string &path)
{
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

    if (fd < 0) {
        fprintf(stderr, "erreur: impossible de creer %s\n", path.c_str());
        return;
    }
    write(fd, DEMO_PCAP, sizeof(DEMO_PCAP));
    close(fd);
}

void send_forbidden(int client)
{
    std::string body = "jeton manquant ou incorrect";
    std::string header = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8"
                        "\r\nContent-Length: " + std::to_string(body.size())
                        + "\r\nConnection: close\r\n\r\n";

    write_all(client, header);
    write_all(client, body);
}

}  // namespace

int main(void)
{
    std::string token = generate_token();
    std::string tmp_dir = make_private_tmp_dir();

    write_demo_pcap(tmp_dir + "/demo.pcap");

    std::string page_html = replace_all(PAGE, "%TOKEN%", token);
    std::string bin_dir = binary_directory();
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        fprintf(stderr, "erreur: impossible de creer la socket\n");
        return 1;
    }

    int reuse = 1;

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    // 127.0.0.1: ce serveur n'ecoute que depuis cette machine, jamais
    // depuis le reseau.
    unsigned char loopback[4] = {127, 0, 0, 1};

    memcpy(&address.sin_addr.s_addr, loopback, sizeof(loopback));
    address.sin_port = to_network_order(static_cast<uint16_t>(PORT));

    if (bind(server_fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) < 0) {
        fprintf(stderr, "erreur: impossible d'ecouter sur le port %d"
                        " (deja utilise ?)\n", PORT);
        close(server_fd);
        return 1;
    }
    listen(server_fd, 8);

    printf("Interface web sur http://127.0.0.1:%d (Ctrl+C pour arreter)\n", PORT);
    printf("Pour que la capture en direct marche, lancez ce programme avec sudo.\n");

    for (;;) {
        int client = accept(server_fd, NULL, NULL);

        if (client < 0)
            continue;

        char buffer[8192];
        ssize_t received = recv(client, buffer, sizeof(buffer) - 1, 0);

        if (received <= 0) {
            close(client);
            continue;
        }
        buffer[received] = '\0';

        std::string request(buffer);
        std::string first_line = request.substr(0, request.find('\r'));

        // Verifie en premier, avant meme de servir la page: voir
        // extract_host() pour ce que cet en-tete dejoue.
        if (!host_is_allowed(extract_host(request))) {
            send_forbidden(client);
            close(client);
            continue;
        }

        if (first_line.find("GET /run") != std::string::npos) {
            // Sans le bon jeton, aucune commande n'est lancee: voir
            // generate_token() pour ce que ca empeche.
            if (extract_param(first_line, "token") != token) {
                send_forbidden(client);
                close(client);
                continue;
            }

            std::string action = extract_param(first_line, "action");

            printf("  -> %s\n", action.c_str());
            send_response(client, "text/plain; charset=utf-8",
                         run_action(action, bin_dir, tmp_dir));
        } else {
            send_response(client, "text/html; charset=utf-8", page_html);
        }
        close(client);
    }

    close(server_fd);
    return 0;
}
