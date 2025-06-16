/*
 Dieses Programm prüft mit Dudect, ob die Funktion `insecure_compare`
 durch Zeitmessung angreifbar ist. Es wird analysiert, ob sich aus
 dem Timing Rückschlüsse auf das geheime Passwort ziehen lassen.
 
 * Link zum dudect GitHub Repository von Dudect https://github.com/oreparaz/dudect?tab=readme-ov-file
 
 * Befehle zum Kompilieren und Ausführen:
   Kompiliern:  gcc -o test_dudect test_dudect.c -O2 -lm
   Ausführen ./test_dudect
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>    // für usleep
#include <time.h>

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

// Länge des Secrets 
#define SECRET_LEN_BYTES 16

// Das geheime Passwort
uint8_t secret[SECRET_LEN_BYTES] = { 's','e','c','r','e','t','p','a','s','s','w','o','r','d','1','2' };

// Unsichere Vergleichsfunktion (ähnlich Python-Version)
int insecure_compare(uint8_t *user_input, uint8_t *secret_password, size_t len) {
    if (len != SECRET_LEN_BYTES) return 0;
    for (size_t i = 0; i < len; i++) {
        if (user_input[i] != secret_password[i]) {
            return 0;
        }
    }
    return 1;
}

// Dudect-Funktion, die wiederholt aufgerufen wird und das Timing misst
uint8_t do_one_computation(uint8_t *data) {
    return insecure_compare(data, secret, SECRET_LEN_BYTES);
}

// Bereitet die Inputs für die Messungen vor
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit(); // Klasse 0 oder 1 zufällig
        if (classes[i] == 0) {
            // Input genau gleich wie das Secret (Klasse 0)
            memcpy(input_data + i * c->chunk_size, secret, c->chunk_size);
        } else {
            // Zufällige Daten (Klasse 1)
            randombytes(input_data + i * c->chunk_size, c->chunk_size);
        }
    }
}

// Starte den Test
int run_test(void) {
    dudect_config_t config = {
        .chunk_size = SECRET_LEN_BYTES,
        .number_measurements = 500,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    // max Laufzeit ca. 120 Sekunden (timeout im externen Skript), hier läuft so lange bis Ergebnis steht
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    dudect_free(&ctx);
    return (int)state;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    int res = run_test();

    if (res == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        printf("Keine Timing-Lecks erkannt.\n");
    } else if (res == DUDECT_LEAKAGE_FOUND) {
        printf("Timing-Leak erkannt!\n");
    } else {
        printf("Testergebnis: %d\n", res);
    }

    return res;
}


// Finale Ausgabe nach vielen Messungen:
// meas: 2448.32 M, max t:   +1.09, max tau: 2.19e-05, (5/tau)^2: 5.20e+10. For the moment, maybe constant time.