import math
def basescore():

    #Stale z wartoscia dla poszczegolnych miar
    AV = [0.2, 0.55, 0.62, 0.85]
    AC = [0.77, 0.44]
    PR = [0.85, 0.62, 0.27]
    PRC = [0.85, 0.62, 0.27]
    UI = [0.85, 0.62]
    CIA = [0, 0.22, 0.56]

    #Obliczamy ISS ze wzoru 1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]
    b = (1 - ((1 - CIA[int(input("Choose value of Confidentiality \n 0 - None \n 1 - Low \n 2 - High"))]) *
              (1 - CIA[int(input("Choose value of Integrity  \n 0 - None \n 1 - Low \n 2 - High"))]) *
              (1 - CIA[int(input("Choose value of Availabity  \n 0 - None \n 1 - Low \n 2 - High"))])))

    # Obliczamy Impact z podzialem na Unchanged i Changed Scope
    c = int(input("Choose scope \n 0 - UnChanged \n 1 - Changed"))
    if c == 0:
        d = b * 6.42
        # d to impact dla Unchanged 6.42 × ISS

        e = (8.22 * (
            (AV[int(input("Choose value of Attack Vector \n 0 - Physical \n 1 - Local \n 2 - Adjacent \n 3 - Network"))] *
             (AC[int(input("Choose value of Attack Complexity  \n 0 - Low \n 1 - High "))]) *
             (PRC[int(input("Choose value of Privileges Required  \n 0 - None \n 1 - Low \n 2 - High"))]) *
             (UI[int(input("Choose value of User Interaction  \n 0 - None \n 1 - Required "))]))))
        # e odpowiada za Exploitability 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction

        f = min(round((d + e), 10),10)* 10
        if b == 0:
            f = 0
        # f to base score dla Unchanged,
        # z zalozeniami ze f nie przekroczy 10 pkt oraz jak ISS jest rowne 0 to caly basescore tez sie rowna 0

    else:
        d = (7.52 * (b - 0.029) - 3.25 * (b - 0.02) ** 15)
        # d to impact dla changed 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15

        e = (8.22 * (
            (AV[int(
                input("Choose value of Attack Vector \n 0 - Physical \n 1 - Local \n 2 - Adjacent \n 3 - Network"))] *
             (AC[int(input("Choose value of Attack Complexity  \n 0 - Low \n 1 - High "))]) *
             (PR[int(input("Choose value of Privileges Required  \n 0 - None \n 1 - Low \n 2 - High"))]) *
             (UI[int(input("Choose value of User Interaction  \n 0 - None \n 1 - Required "))]))))
        # e odpowiada za Exploitability 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
        print("ISS: ", b, "Impact: ", d, "Explo: ", e)
        f = min(round(1.08 * (d + e), 10),10) *10

        if b == 0:
            f = 0
        # f to base score dla changed,
        # z zalozeniami ze f nie przekroczy 10 pkt oraz jak ISS jest rowne 0 to caly basescore tez sie rowna 0


    if 90 <= f < 100:
        print("Basescore: ", math.ceil(f) /10, " (Critical)")
    if 70 <= f < 90:
        print("Basescore: ", math.ceil(f) /10, " (High)")
    if 40 <= f < 70:
        print("Basescore: ", math.ceil(f) /10, " (Medium)")
    if 0 < f < 40:
        print("Basescore: ", math.ceil(f) /10, " (Low)")
    elif f == 0:
        print("Basescore: ", f, " (None)")

    #Wypisujemy CVSS score oraz Rating


basescore()

