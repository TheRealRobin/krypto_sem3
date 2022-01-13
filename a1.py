# Autor: Robin Böhn (2021) | IT-SEC 3.Semester Kryptologie | Leibniz-FH Hannover
# Zu Aufgabe 1 der Klausurersatzleistung
# Gibt verschieden formatierte Bit Listen mit ver- und entschlüsselten Daten aus

# DIESE VARIABLEN ANPASSEN ----
plaintext = "Hallo Bob, Grüße von Alice!"    # Länge egal, Nur ANSI-Konforme Zeichen erlaubt
key_12bit = "011001110010"                   # Muss genau 12 Bit lang sein. Nur 0 oder 1 erlaubt
# -----------------------------

# Script startet hier
from bitstring import BitArray # einfache Bitstring-Klasse, mit der sich gut arbeiten lässt 
import mini_des # modul von mir selbst, enthält die eigentlíche Logik für die Verschlüsselung

P = mini_des.slice_text(plaintext,"ansi") # Übersetzt aus menschenlesbarem Text in einzelne Bytes, mit dem spezifizierten Encoding
K = BitArray(str("0b"+key_12bit))         # Constructor für den K_DES-Bitstring
E = [mini_des.encrypt_block(X,K) for X in P]  # Verschlüsselt alle einzelnen Plaintext-Bytes
D = [mini_des.decrypt_block(X,K) for X in E]  # Entschlüsselt alle einzelnen Geheimtext-Bytes
decrypted_text = mini_des.unslice_text(D,"ansi") # Übersetzt einzelne Bytes in menschenlesbaren Text, mit dem spezifizierten Encoding

# Der Rest ist nur Output-Formatierung
E_LABELED_BYTES = [(", X_" + str(i+1)+ "=" + str(E[i].bin)) for i in range( len(E) )]
D_LABELED_BYTES = [(", B_" + str(i+1)+ "=" + str(D[i].bin)) for i in range( len(D))]
E_JUST_BYTES = BitArray()
[E_JUST_BYTES.append(X) for X in E]
D_JUST_BYTES = BitArray()
[D_JUST_BYTES.append(B) for B in D]

# und Ausgabe der berechneten Werte
[print(X,end="") for X in E_LABELED_BYTES] # Gibt alle Bytes X_n aus dem Geheimtext aus
print("")
[print(B,end="") for B in D_LABELED_BYTES] # Gibt alle Bytes B_n aus dem entschlüsselten Geheimtext aus
print("")
print(E_JUST_BYTES.hex)                    # Gibt den Geheimtext als Hexadezimalzahl aus
print("")
print(D_JUST_BYTES.hex)                    # Gibt den entschlüsselten Geheimtext als Hexadezimalzahl aus
print("")

print(plaintext)
print(decrypted_text)