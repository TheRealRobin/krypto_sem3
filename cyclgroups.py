#https://crypto.stackexchange.com/questions/9006/how-to-find-generator-g-in-a-cyclic-group
# Comment from "poncho"

from mpmath.libmp.libintmath import isprime
from random import randint

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

def find_schnorr(q):
    P = [(k*q)+1  for k in range(100)] # okay val for k is 36
    i = -1
    for p in P:
        i += 1
        if isprime(p):
            print(f"{p}, k={i}") # finde primzahl = (k*q)+1 für irgendein k
        else:
            pass

if __name__ == "__main__":
    q = 2300025137 # q ist prim, dies ist mein Startwert
    find_schnorr(q) # first value will be 82800904933 with k=36
    p = 82800904933
    find_generator(p,q)

# after some testing, I found that these values should be okay:
# q = 2300025137
# p = (k*q)+1 für k=36  = 82800904933
# p is now a so called "Schnorr Prime"