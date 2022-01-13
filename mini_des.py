from bitstring import BitArray, pack as __pack

def slice_text(plaintxt: str, encoding: str) -> list(BitArray()):
    bytearr = plaintxt.encode(encoding,"strict")
    plainbits = BitArray(bytes=bytearr)
    slices = []
    for r in range(0, len(plainbits), 8):
        slice = plainbits[r:r+8]
        if len(slice) == 8:
            slices.append(slice)
            continue
        else:
            raise RuntimeError("Slice should be 8 bits long, is " + len(slice) + " bits long instead. Please investigate!")
    return slices

def unslice_text(plainslices: list,encoding: str) -> str:
    concat = BitArray()
    for slice in plainslices:
        concat.append(slice)
    encoded_bytes = concat.bytes
    plaintxt = encoded_bytes.decode(encoding,"ignore")
    return plaintxt

# Die gesamte Funktionsweise des MiniDES-Algorithmus basiert auf der Vorlesung von Prof. Matthes
def __expand_input(inp: BitArray) -> BitArray(length=6):
    inp_4 = BitArray(length=4)
    if len(inp) <= 4:
        if len(inp) < 4:
            amount_of_leading_zeroes = 4 - len(inp)
            inp_4.overwrite(inp, amount_of_leading_zeroes)
        elif len(inp) == 4:
            inp_4 = inp
        result = __pack("bool=b1, bool=b4, bool=b3, bool=b2, bool=b4, bool=b1", b1=inp_4[0], b2=inp_4[1], b3=inp_4[2], b4=inp_4[3])
        return result
    else: raise ValueError("Length of Input BitArray has to be between 0 and 4")

def __xor(a: BitArray, b: BitArray) -> BitArray:
    if len(a) == len(b):
        xor = BitArray()
        i = 0
        while i < len(a):
            if (a[i] and b[i]):
                xor.append('0b0')
            elif (a[i] and not b[i]):
                xor.append('0b1')
            elif (not a[i] and b[i]):
                xor.append('0b1')
            elif (not a[i] and not b[i]):
                xor.append('0b0')
            i += 1
        return xor
    else: raise ValueError("a and b need to be of the same length!")

def __s_box(xorin: BitArray) -> BitArray:
    s1 = [[0,3,1,2],
          [2,3,0,1]] # c123 = 0 00
    s2 = [[2,1,3,0],
          [0,1,2,3]] # c456 = 1 01
    d1234 = BitArray(length=4) # 4bit result
    if len(xorin) == 6: #input needs to be 6 bit
        
        c123 = xorin[0:3]
        c456 = xorin[3:6]

        # c123 -> S1
        if c123[0]: #c1=1
            col = 1
            val = c123[1:3].uint #c2 c3 determine val: 0,1,2,3
            d12 = BitArray(uint=s1[col][val], length=2)
            d1234.overwrite(d12[0:2],0)
        else: #c1=0
            col = 0
            val = c123[1:3].uint #c2 c3 determine val: 0,1,2,3
            d12 = BitArray(uint=s1[col][val], length=2)
            d1234.overwrite(d12[0:2],0)

        # c456 -> S2
        if c456[0]: #c4=1
            col = 1
            val = c456[1:3].uint #c5 c6 determine val: 0,1,2,3
            d34 = BitArray(uint=s2[col][val], length=2)
            d1234.overwrite(d34[0:2],2)
        else: #c4=0
            col = 0
            val = c456[1:3].uint #c5 c6 determine val: 0,1,2,3
            d34 = BitArray(uint=s2[col][val], length=2)
            d1234.overwrite(d34[0:2],2)
    return d1234

def __mini_des_step(round_input: BitArray(length=4), round_key: BitArray(length=6)) -> BitArray(length=4):
    expin = __expand_input(round_input)     # expand input (4bit -> 6bit)
    xorin = __xor(expin, round_key)         # XOR with key (6bit -> 6bit)
    sboxd = __s_box(xorin)                  # Feed into S-Boxes (6bit -> 4bit)
    return sboxd                            # return the cyphertext for this step

def encrypt_block(lr: BitArray, key: BitArray) -> BitArray:
    l0 = lr[0:4]
    r0 = lr[4:8]
    k0 = key[0:6]
    l1 = r0
    r1 = __xor(__mini_des_step(r0,k0),l0)
    l2 = r1
    k1 = key[6:12]
    r2 = __xor(__mini_des_step(r1,k1),l1)
    result = BitArray()
    result.append(l2)
    result.append(r2)
    return result

def decrypt_block(lr: BitArray, key: BitArray) -> BitArray:
    l2 = lr[0:4]
    r2 = lr[4:8]
    k1 = key[6:12]
    r1 = l2
    l1 = __xor(__mini_des_step(r1,k1),r2)
    k0 = key[0:6]
    r0 = l1
    l0 = __xor(__mini_des_step(r0,k0),r1)
    result = BitArray()
    result.append(l0)
    result.append(r0)
    return result

if __name__ == "__main__":
    print("This file should not be run as a script, only imported as a module!")