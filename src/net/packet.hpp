#pragma once

#include <stddef.h>
#include <stdint.h>

// Un paquet, tel qu'il nous parvient.
//
// La meme structure sert dans les deux sens: elle decrit aussi bien un paquet
// qui vient d'arriver sur la carte reseau qu'un paquet relu dans un fichier.
// C'est pour ca qu'elle vit ici, dans net/, et non dans capture/ ou storage/:
// les deux s'en servent, aucun des deux ne la possede.
struct CapturedPacket {
    // Pointe dans le tampon de celui qui l'a produit, capture ou fichier.
    // Valable jusqu'au prochain paquet demande, pas au-dela.
    const uint8_t *data;

    size_t length;           // ce qu'on a reellement recupere
    size_t original_length;  // la taille reelle sur le cable, souvent la meme
    long seconds;            // date de capture
    long microseconds;
};
