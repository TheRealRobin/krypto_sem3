from mpmath.libmp.libintmath import isprime
from random import randint

# https://crypto.stackexchange.com/questions/9006/how-to-find-generator-g-in-a-cyclic-group
# find_schnorr und find_generator basieren auf einem Kommentar des Benutzers "poncho"
def find_schnorr(q):
    P = [(k*q)+1  for k in range(100)] # okay val for k is 36
    i = -1
    for p in P:
        i += 1
        if isprime(p):
            print(f"p={p}, k={i}") # finde primzahl = (k*q)+1 für irgendein k
            return p, i
        else:
            pass

def find_generator(p,q):
    while True:
        h = randint(2,p-1)
        g = (int(h)^ ((int(p)-1) // int(q)) ) % int(p) # ( h hoch ( (p-1) / q ) ) modulo p
        if g == 1:
            continue
        elif g != 1:
            print(str(f"h   = {h}"))
            print(str(f"g   = {g}")) # g is the found generator
            break

# extended_euclid basiert auf rekursivem pseudocode von https://de.wikipedia.org/wiki/Erweiterter_euklidischer_Algorithmus#Rekursive_Variante_2
def extended_euclid(a:int,n:int):
    if (n==0):
        return a, 1, 0
    d_, s_, t_ = extended_euclid(n, (a % n))
    d, s, t = (d_, t_, s_ - ( a // n )*t_)
    return d, s, t # d is ggT(a,n), s ist a^-1 in Z_n

def find_inverse_of(KeyDH, p):
    d, s, t = extended_euclid(KeyDH, p)
    print(f"d={d} ,s={s}, t={t}")
    InvKeyDH = s % p
    print(f"s={InvKeyDH}")
    print(f"{((InvKeyDH*KeyDH) % p)}={InvKeyDH}*{KeyDH} mod {p}")
    return InvKeyDH

if __name__ == "__main__":
    q = 2300025137 # q ist prim, dies ist mein Startwert
    p, k = find_schnorr(q) # Erster Wert, der hiervon gefunden wird ist p= 82800904933 mit k=36
    # g = find_generator(p,q) # 50403857261 war der Wert, den diese Funktion bei meinem ersten Ausführen geliefert hat, und war daher auch der in meinen Berechnungen verwendete. Wurde in dieser Version auskommentiert, da find_generator bei jedem Ausführen einen zufällig gefundenen Generator für Z_p ausgibt und daher nur einmal benötigt wurde
    g = 50403857261
    KeyDH = 7892505325 # wurde separat ausgerechnet, indem Alice und Bob sich mithilfe des Diffie-Hellman-Verfahrens auf ein gemeinsames Geheimnis einigen. Siehe dafür die Berechnungen in Aufgabe 2 in der abgegebenen pdf-Datei.
    InvKeyDH = find_inverse_of(KeyDH, p)
    print(f"q= {q}, p= {p}, k={k}, g={g}, InvKeyDH={InvKeyDH}")