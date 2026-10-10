# Un seul programme de test, un fichier par module teste.
add_executable(tests
    main.cpp
    test_bytes.cpp
    test_mac.cpp
    test_ipv4.cpp
    test_iface.cpp
    test_dissect.cpp
    test_pcap.cpp
    test_filter.cpp
    test_analysis.cpp
    test_log.cpp
    test_color.cpp
)
target_link_libraries(tests sniffer)
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME unitaires COMMAND tests)

# Verifications sur le programme lui-meme.
add_test(NAME version COMMAND mysniffer --version)
set_tests_properties(version PROPERTIES PASS_REGULAR_EXPRESSION "^${PROJECT_VERSION}")

add_test(NAME interfaces COMMAND mysniffer interfaces --all)
set_tests_properties(interfaces PROPERTIES PASS_REGULAR_EXPRESSION "NOM")

# Une commande inconnue doit sortir en erreur.
add_test(NAME commande_inconnue COMMAND mysniffer nimportequoi)
set_tests_properties(commande_inconnue PROPERTIES WILL_FAIL TRUE)

# La lecture d'un fichier absent doit echouer proprement.
add_test(NAME fichier_absent COMMAND mysniffer read -r /nexiste/pas.pcap)
set_tests_properties(fichier_absent PROPERTIES WILL_FAIL TRUE)

# La commande read sans fichier doit expliquer ce qui manque.
add_test(NAME read_sans_fichier COMMAND mysniffer read)
set_tests_properties(read_sans_fichier PROPERTIES WILL_FAIL TRUE)

# Un reglage de couleur inconnu doit etre refuse, pas ignore en silence.
add_test(NAME couleur_invalide COMMAND mysniffer read --color bleu)
set_tests_properties(couleur_invalide PROPERTIES WILL_FAIL TRUE)
