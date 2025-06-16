/*
   Dieses Programm  testet ob TIMCOP in der Lage ist die Schwachstelle im
   nicht-zeitkonstatnen Stringvergleich zu erkennen., 
 
   Mithilfe von Timecop wird das geheime Passwort (`secret`) vor dem Vergleich explizit als 
   „nicht initialisierter Speicher“ markiert (`poison`). Dadurch kann Timecop erkennen, 
   ob und wie oft an kritischen Code Stellen wie "if-Abzweigungen" 
   auf das geheim markierte Memory zugegriffen wurde. 
   Dies erlaubt eine Analyse von potenziellen Seitenkanälen und Timing-Leaks.

   Linke zur Webseite von TIMECOP https://www.post-apocalyptic-crypto.org/timecop/
   
   Befehle zum Kompilieren und Ausführen:
   gcc -g -O3 test_timecop.c -o test_timecop  
   valgrind --track-origins=yes ./test_timecop
 */


#include <stdio.h>
#include <string.h>
#include "poison.h"

// Unsicherer Stringvergleich: bricht bei erstem Unterschied ab
int insecure_compare(const char* user_input, const char* secret) {
    size_t len_user = strlen(user_input);
    size_t len_secret = strlen(secret);

    if (len_user != len_secret;) {
        return 0;
    }

    for (size_t i = 0; i < len_secret; i++) {
        if (user_input[i] != secret[i]) {
            return 0;
        }
    }

    return 1;
}

int main() {
    const char* input = "hallo123";
    const char* secret = "hello123";

    // Markiere das Secret als geheim
    poison((void*)secret, strlen(secret));

    int result = insecure_compare(input, secret);

    // Optional: gib Ergebnis aus
    printf("Vergleich: %s\n", result ? "Match" : "No Match");

    return 0;
}



/*
Finale Ausgabe mit Timecop und Valgrind:

==23557== Memcheck, a memory error detector
==23557== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==23557== Using Valgrind-3.25.1 and LibVEX; rerun with -h for copyright info
==23557== Command: ./example2
==23557== 
==23557== Conditional jump or move depends on uninitialised value(s)
==23557==    at 0x484B109: __strlen_sse2 (vg_replace_strmem.c:508)
==23557==    by 0x400127D: insecure_compare (example2.c:8)
==23557==    by 0x4001120: main (example2.c:32)
==23557==  Uninitialised value was created by a client request
==23557==    at 0x400110B: main (example2.c:32)
==23557== 
==23557== Conditional jump or move depends on uninitialised value(s)
==23557==    at 0x484B118: __strlen_sse2 (vg_replace_strmem.c:508)
==23557==    by 0x400127D: insecure_compare (example2.c:8)
==23557==    by 0x4001120: main (example2.c:32)
==23557==  Uninitialised value was created by a client request
==23557==    at 0x400110B: main (example2.c:32)
==23557== 
==23557== Conditional jump or move depends on uninitialised value(s)
==23557==    at 0x40012A1: insecure_compare (example2.c:15)
==23557==    by 0x4001120: main (example2.c:32)
==23557==  Uninitialised value was created by a client request
==23557==    at 0x400110B: main (example2.c:32)
==23557== 
Vergleich: No Match
==23557== 
==23557== HEAP SUMMARY:
==23557==     in use at exit: 0 bytes in 0 blocks
==23557==   total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==23557== 
==23557== All heap blocks were freed -- no leaks are possible
==23557== 
==23557== For lists of detected and suppressed errors, rerun with: -s
==23557== ERROR SUMMARY: 10 errors from 3 contexts (suppressed: 0 from 0)

*/
