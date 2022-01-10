# Autor: Robin Böhn (2021) | IT-SEC 3.Semester Kryptologie | Leibniz-FH Hannover
# Zu Aufgabe 1 der Klausurersatzleistung
# Gibt den gewählten Text als Cyphertext nach MiniDES Verschlüsselung aus

# DIESE VARIABLEN ANPASSEN ----
plaintext = "Hallo Bob, Grüße von Alice!"    # Länge egal, Nur ANSI-Konforme Zeichen erlaubt
key_12bit = "011001110010"                   # Muss genau 12 Bit lang sein. Nur 0 oder 1 erlaubt
# -----------------------------

# Script starts here
from bitstring import BitArray # macht es viel einfacher mit Bitstrings zu arbeiten
import mini_des # modul von mir selbst, enthält die Logik für die Verschlüsselung selbst

P = mini_des.slice_text(plaintext,"ansi") # slice plaintext into small 8bit blocks
K = BitArray(str("0b"+key_12bit))         # Construct key BitArray
E = [mini_des.encrypt_block(X,K) for X in P]  # Loops through all blocks and encrypts them with MiniDES
D = [mini_des.decrypt_block(X,K) for X in E]  # Loops throung all cypher-blocks and decrypts them with MiniDES
decrypted_text = mini_des.unslice_text(D,"ansi")

# Rest ist nur Output-Formatting
LABELED_BYTES = [(", X_" + str(i+1)+ "=" + str(E[i].bin)) for i in range( len(P) )]
JUST_BYTES = BitArray()
[JUST_BYTES.append(X) for X in E]
[print(X,end="") for X in LABELED_BYTES] # Outputs all Bytes X_n of G seperately
print("")
print(JUST_BYTES.hex)                    # Outputs all Bytes X_n of G as hex string
print("")
print(plaintext)
print(decrypted_text)