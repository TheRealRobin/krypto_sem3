from bitstring import BitArray

sym_key = BitArray('0b101010110101011010101')
print(len(sym_key))

diff = 6 - len(sym_key) % 6
zeroes = BitArray(diff * '0b0')

print(diff)
print(zeroes)