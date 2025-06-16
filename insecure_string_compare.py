"""
Timing-Angriff auf einen unsicheren String-Vergleich

Ziel:
Demonstration, wie unsichere Passwortvergleiche durch Timing-Analyse angegriffen werden können
und wie sich daraus das geheime Passwort schrittweise rekonstruieren lässt.


Ablauf:

1. Definition eines geheimen Passworts (SECRET), das typischerweise auf einem Server gespeichert wäre.

2. Implementierung zweier Vergleichsfunktionen:
   - insecure_compare: Vergleicht Zeichen für Zeichen und bricht beim ersten Fehler ab,
     mit künstlicher Verzögerung pro Zeichen, was Laufzeitunterschiede verursacht.
   - secure_compare: Zeitkonstanter Vergleich mit hmac.compare_digest zur Vermeidung von Timing-Angriffen.

3. Angriffssimulation:
   - estimate_password_length misst, ob man anhand der Laufzeit den Passwortlänge abschätzen kann.
   - guess_password führt einen Zeichen-für-Zeichen Timing-Angriff durch,
     indem es für jede Position alle möglichen Zeichen testet und das mit der längsten Laufzeit
     als wahrscheinlich richtiges Zeichen annimmt.

4. Visualisierung:
   - create_combined_plots erzeugt eine PDF/grafische Ausgabe mit
     - Dichteplots der Laufzeitverteilungen für verschiedene Passwortlängen
     - Heatmap der Vergleichszeiten pro getesteter Zeichenposition und Zeichen

"""

import time
import string
import hmac
import numpy as np
import seaborn as sns
import string
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import seaborn as sns


# ----------------------------------------
# TEIL 1: ANNAHME – "Serverseitige" Logik
# ----------------------------------------

# In der Realität würde dieses Passwort z. B. auf einem Server gespeichert sein.
# Hier simulieren wir es lokal für den Angriff.
SECRET = "topsecret"

def insecure_compare(user_input: str, secret_password: str) -> bool:
    len_user = len(user_input)
    len_secret = len(secret_password)
    if len_user != len_secret:
        return False
    for i in range(len_user):
        if user_input[i] != secret_password[i]:
            return False
        time.sleep(0.005)  # Kleine künstliche Verzögerung, um geringe Zeitunterschiede besser messbar zu machen
    return True


def secure_compare(a: str, b: str) -> bool:
    """
    Sichere Vergleichsfunktion mit konstanter Laufzeit.
    Verwendet Python-Standardbibliothek (hmac.compare_digest).
    """
    return hmac.compare_digest(a, b)

# ----------------------------------------
# TEIL 2: Angriffssimulation (Timing Attack)
# ----------------------------------------

def measure_timing(compare_func, guess: str, repetitions: int = 5) -> float:
    """
    Misst die durchschnittliche Laufzeit eines Vergleichs.
    Mehrere Wiederholungen für Robustheit gegen zufällige Schwankungen.
    """
    times = []
    for _ in range(repetitions):
        start = time.perf_counter()
        compare_func(guess, SECRET)
        end = time.perf_counter()
        times.append(end - start)
    return sum(times) / len(times)


def estimate_password_length(max_len=20, trials_per_len=100):
    """
    Führt Timing-Messungen für verschiedene Passwortlängen durch.
    Ziel: Überprüfung, ob sich die Passwortlänge über mittlere Laufzeit schätzen lässt.
    """
    lengths = [3,6,9,12,15] # list(range(1, max_len + 1))
    all_timings = []

    for length in lengths:
        guess = "a" * length
        trial_timings = [measure_timing(insecure_compare, guess, 1) for _ in range(trials_per_len)]
        all_timings.append(trial_timings)

    # Mittelwerte berechnen
    avg_timings = [np.mean(timings) for timings in all_timings]
    best_index = int(np.argmax(avg_timings))
    estimated_length = lengths[best_index]
    print(f"\n Geschätzte Passwortlänge: {estimated_length} (basierend auf maximaler mittlerer Zeit)")


    return lengths, all_timings

# Durchführung einer Ratesession mit Heatmap-Daten
def guess_password():
    charset = string.ascii_lowercase
    guessed_pw = ""
    heatmap_data = []
    best_chars = []

    for i in range(len(SECRET)):
        row = []
        for c in charset:
            # Aufbau der Vermutung (z. B. "taa..." für Stelle 1 mit "t")
            guess = guessed_pw + c + "a" * (len(SECRET) - len(guessed_pw) - 1)
            t = measure_timing(insecure_compare, guess, 100)
            row.append(t)
        # Bestes Zeichen anhand längster Zeit
        best_index = int(np.argmax(row))
        best_char = charset[best_index]
        best_chars.append(best_index)
        guessed_pw += best_char
        heatmap_data.append(row)
        print(f"Position {i+1}: Best guess so far: {guessed_pw}")
    
    print(f"\n✅ Final guessed secret: {guess}")
    
    return np.array(heatmap_data), guessed_pw, best_chars



def create_combined_plots(heatmap_data, best_chars, secret, lengths, all_timings):
    # Gesamtlayout für DIN A4 (in Zoll)
    plt.figure(figsize=(8.27, 11.69))  # 21cm x 29.7cm in inches
    plt.figure(figsize=(8.27, 4.3)) 
    gs = GridSpec(2, 1, height_ratios=[1, 1.5], hspace=0.7)  # Mehr Platz und Reihenfolge
    
    # Stileinstellungen
    sns.set_style("whitegrid")
    plt.rcParams['font.size'] = 10
    plt.rcParams['axes.titlesize'] = 12
    plt.rcParams['axes.labelsize'] = 11
    
    # Erster Plot: Längenverteilung (oben)
    ax1 = plt.subplot(gs[0])
    
    # Farbpalette für Längen vorbereiten
    colors = sns.color_palette("husl", len(lengths))
    correct_length_idx = lengths.index(len(secret))
    
    for i, (length, timings) in enumerate(zip(lengths, all_timings)):
        if length == len(secret):
            linewidth = 2.5
            linestyle = '-'
            color = "#2ca02c" # '#d62728'  # Auffälliges Rot
            alpha = 1.0
            zorder = 3
            label = f"Länge {length} (korrekt)"
        else:
            linewidth = 1.2
            linestyle = '-'  # "--"
            color = colors[i]
            alpha = 0.6
            zorder = 1
            label = f"Länge {length}"
            
        sns.kdeplot(timings, 
                    label=label,
                    linewidth=linewidth,
                    linestyle=linestyle,
                    color=color,
                    alpha=alpha,
                    zorder=zorder,
                    ax=ax1)
    
    # Vertikale Linie für Median der korrekten Länge
    median_correct = np.median(all_timings[correct_length_idx])
    ax1.axvline(median_correct, color='#2ca02c', linestyle=':', alpha=0.7, linewidth=1.5)
    ax1.text(median_correct*1.01, ax1.get_ylim()[1]*0.9, 
             f"Median: {median_correct:.2e}s",
             color='#2ca02c',
             fontsize=9)
    
    ax1.set_title("A) Laufzeitunterschiede bei verschiedenen Passwortlängen", pad=10, fontsize=12)
    ax1.set_xlabel("Vergleichsdauer [s]")
    ax1.set_ylabel("Dichte")
    ax1.legend(title="Passwortlängen", fontsize=9, title_fontsize=10, ncol=2)
    ax1.set_xlim(left=0, right=0.4e-5)
    ax1.grid(True, linestyle=':', alpha=0.5)
    
    # Zweiter Plot: Heatmap (unten)
    ax2 = plt.subplot(gs[1])
    im = ax2.imshow(heatmap_data, cmap="YlOrRd", aspect="auto", 
                    vmin=0, vmax=max(heatmap_data.max(), 0.1))
    
    # Colorbar kompakt gestalten
    cbar = plt.colorbar(im, ax=ax2, fraction=0.046, pad=0.04)
    cbar.set_label("Vergleichsdauer [s]", fontsize=10)
    
    # Achsen optimieren
    charset = list(string.ascii_lowercase)
    ax2.set_xticks(range(len(charset)))
    ax2.set_xticklabels(charset, fontsize=9)
    ax2.set_yticks(range(len(secret)))
    #ax2.set_yticklabels([f"Position {i+1} (richtig: '{secret[i]}')" for i in range(len(secret))], fontsize=9)
    ax2.set_yticklabels([f"{i+1}: '{secret[i]}'" for i in range(len(secret))], fontsize=9)
  
    # Markierungen
    ax2.scatter(best_chars, range(len(best_chars)), 
                s=100, facecolors='none', edgecolors='darkgreen', 
                linewidths=1.5, marker='X', label='Korrekt geraten')
    
    ax2.set_title("B) Zeichenweise Rekonstruktion mittels Timing-Angriff", pad=10, fontsize=12)
    ax2.set_xlabel("Getestete Zeichen")
    ax2.set_ylabel("Passwortposition")
    ax2.legend(loc='upper right', fontsize=9)
    ax2.grid(True, linestyle=':', alpha=0.5)

    # Gesamtspeicherung
    plt.tight_layout()
    plt.savefig("combined_timing_analysis.png", 
                dpi=600, 
                bbox_inches='tight', 
                facecolor='white')
    # plt.show()



# ----------------------------------------
# MAIN-Teil: Hier wird das Skript ausgeführt
# ----------------------------------------

if __name__ == "__main__":
    lengths, all_timings = estimate_password_length(max_len=15, trials_per_len=100)
    heatmap_data, guessed_password, best_chars = guess_password()
    create_combined_plots(heatmap_data, best_chars, SECRET, lengths, all_timings)






