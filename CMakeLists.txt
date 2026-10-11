cmake_minimum_required(VERSION 3.16)

project(mysniffer
    VERSION 0.1.0
    DESCRIPTION "Analyseur de paquets reseau multiplateforme"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Type de build" FORCE)
endif()

# Le sujet exige zero warning. -Wall -Wextra (ou /W4 sous MSVC) attrape la
# grande majorite des erreurs classiques. WARNINGS_AS_ERRORS est active par la CI.
if(MSVC)
    add_compile_options(/W4)
    # MSVC signale comme "deprecated" des fonctions standard (fopen, strerror,
    # sprintf...) au profit de ses propres variantes "_s", non portables.
    # Ce sont des fonctions C ordinaires, utilisees correctement: on ne
    # reecrit pas le code pour une seule plateforme, on tait juste l'avis.
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra)
endif()

option(WARNINGS_AS_ERRORS "Transformer les warnings en erreurs" OFF)
if(WARNINGS_AS_ERRORS)
    if(MSVC)
        add_compile_options(/WX)
    else()
        add_compile_options(-Werror)
    endif()
endif()

option(SANITIZE "Activer les sanitizers (detection de bugs memoire)" OFF)
if(SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# La capture ne se fait pas du tout de la meme facon selon le systeme.
# Chaque version est dans son propre fichier, et on compile celle qui va bien.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CAPTURE_SOURCE src/capture/capture_linux.cpp)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD|Darwin")
    set(CAPTURE_SOURCE src/capture/capture_bsd.cpp)
elseif(WIN32)
    set(CAPTURE_SOURCE src/capture/capture_windows.cpp)
else()
    message(FATAL_ERROR
        "Systeme non supporte: ${CMAKE_SYSTEM_NAME}. Supportes: Linux, FreeBSD, macOS, Windows.")
endif()
message(STATUS "Capture: ${CAPTURE_SOURCE}")

# Toute la logique vit dans une bibliotheque, pour que le programme et les
# tests utilisent exactement le meme code.
add_library(sniffer STATIC
    src/net/bytes.cpp
    src/net/mac.cpp
    src/net/ipv4_address.cpp
    src/net/checksum.cpp
    src/capture/interface.cpp
    src/dissect/arp.cpp
    src/dissect/ethernet.cpp
    src/dissect/icmp.cpp
    src/dissect/ipv4.cpp
    src/dissect/tcp.cpp
    src/dissect/udp.cpp
    src/dissect/decode.cpp
    src/log/log.cpp
    src/analysis/analysis.cpp
    src/analysis/report.cpp
    src/filter/filter.cpp
    src/filter/parse.cpp
    src/term/color.cpp
    src/dissect/summary.cpp
    src/storage/pcap.cpp
    ${CAPTURE_SOURCE}
)
target_include_directories(sniffer PUBLIC src)

# Windows est la seule exception a la regle "aucune bibliotheque reseau":
# Winsock2 seul ne donne jamais l'en-tete Ethernet sur ce systeme, et Npcap
# est le moyen reconnu d'obtenir la trame brute sans ecrire un pilote.
# Voir src/capture/capture_windows.cpp et docs/PRIVILEGES.md pour le detail.
if(WIN32)
    set(NPCAP_SDK_DIR "" CACHE PATH "Dossier du SDK Npcap (contient Include/ et Lib/)")
    if(NOT NPCAP_SDK_DIR)
        message(FATAL_ERROR
            "NPCAP_SDK_DIR n'est pas defini. Telechargez le SDK Npcap et passez"
            " -DNPCAP_SDK_DIR=chemin_vers_le_sdk. Voir docs/BUILD.md.")
    endif()
    target_include_directories(sniffer PUBLIC "${NPCAP_SDK_DIR}/Include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_directories(sniffer PUBLIC "${NPCAP_SDK_DIR}/Lib/x64")
    else()
        target_link_directories(sniffer PUBLIC "${NPCAP_SDK_DIR}/Lib")
    endif()
    target_link_libraries(sniffer PUBLIC wpcap Iphlpapi Ws2_32)

    # wpcap.dll n'existe que si Npcap est installe. Sans chargement retarde,
    # meme "mysniffer --version" ou "interfaces" refuserait de demarrer sur
    # une machine sans Npcap, alors que seule la capture en a vraiment besoin
    # (voir capture_windows.cpp). Avec /DELAYLOAD, la DLL n'est chargee qu'au
    # premier appel a une fonction Npcap, dans capture_open.
    if(MSVC)
        target_link_libraries(sniffer PUBLIC delayimp)
        target_link_options(sniffer PUBLIC "/DELAYLOAD:wpcap.dll")
    endif()
endif()

add_executable(mysniffer
    src/cli/main.cpp
    src/cli/commands.cpp
)
target_link_libraries(mysniffer sniffer)
target_compile_definitions(mysniffer PRIVATE MYSNIFFER_VERSION="${PROJECT_VERSION}")

option(BUILD_TESTS "Compiler les tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Bonus: interface web locale. Outil de demonstration pour cette machine,
# pas un livrable multiplateforme: on ne le compile que sous Linux, pour ne
# prendre absolument aucun risque sur les trois autres systemes.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(mysniffer-gui src/gui/server.cpp)
endif()

# Installation: "cmake --install build" copie le programme dans le systeme.
include(GNUInstallDirs)
install(TARGETS mysniffer RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
