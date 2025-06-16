# Seitenkanal "Zeit": Verstehen, Erkennen und Abwehren von Timing-Angriffen

Dieses Repository enthält die Materialien, die im Rahmen eines Projekts zur Untersuchung von **Timing-Angriffen** erstellt wurden. Das Projekt befasste sich mit der Funktionsweise von Timing-Leaks, deren praktischer Demonstration durch Simulationen und der Evaluierung von Tools zur Erkennung solcher Schwachstellen.


### Beschreibung der Dateien und Verzeichnisse:

* **`insecure_string_compare.py`**: Eine Python-Skript-Datei, die eine **nicht-konstantzeitige Stringvergleichsfunktion** implementiert. Diese Datei wurde für die praktische Simulation eines Timing-Angriffs genutzt, um die prinzipielle Ausnutzung von Zeitunterschieden zur Rekonstruktion geheimer Informationen zu demonstrieren. Hier wird durch zeitunterschiede in der Implementierung die korrekte Passwort Länge ermittelt und das Passwort schrittweise rekonstruiert.

* **`dudect/`**: Enthält die notwendigen Dateien für die Integration und den Test mit dem **Dudect**-Framework. Dudect ist ein statistisches Tool zur Detektion von Timing-Leaks in C-Code.
    * `dudect.h`: Header-Datei des Dudect-Frameworks.
    * `test_dudect`: Kompilierte ausführbare Datei des Dudect-Tests.
    * `test_dudect.c`: Der C-Code, der die zu testende Funktion (z.B. den unsicheren Stringvergleich) in das Dudect-Framework einbindet.
* **`TimeCop/`**: Enthält die Dateien zur Integration und zum Test mit **TimeCop**. TimeCop ist ein dynamisches Analyse-Tool, das auf Valgrind basiert und datenabhängige Kontrollflüsse zur Erkennung von Timing-Leaks identifiziert.
    * `memcheck.h`, `poison.h`, `valgrind.h`: Header-Dateien, die für die Integration mit Valgrind/TimeCop notwendig sind.
    * `test_timecop`: Kompilierte ausführbare Datei des TimeCop-Tests.
    * `test_timecop.c`: Der C-Code, der die zu testende Funktion (z.B. den unsicheren Stringvergleich) in das TimeCop-Framework einbindet.


