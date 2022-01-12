#ripped from stackoverflow
def generators(n):
    s = set(range(1, n))
    for a in s:
        g = set()
        for x in s:
            g.add((a**x) % n)
        if g == s:
            print(a)
    return

if __name__ == "__main__":
    my_n = 6354877913
    generators(my_n)