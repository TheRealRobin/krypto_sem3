from bitstring import BitArray, pack

def slice_plaintext(plaintxt: str) -> list(BitArray()): # splits given string into list of BitArrays each of length 8.
    bytearr = plaintxt.encode("utf-8","strict")
    plainbits = BitArray(bytes=bytearr) #convert str to BitArray
    slices = []
    for r in range(0, len(plainbits), 8):
        slice = plainbits[r:r+8]
        if len(slice) == 8:
            slices.append(slice)
            continue
        else:
            raise RuntimeError("Slice should be 8 bits long, is " + len(slice) + " bits long instead. Please investigate!")
    return slices

def unslice_plaintext(plainslices: list) -> str: # reverses slice_plaintext: uses list of 8-bit long BitArrays to reconstruct unicode strings
    concat = BitArray()
    for slice in plainslices:
        concat.append(slice)
    encoded_bytes = concat.bytes
    plaintxt = encoded_bytes.decode("utf-8","strict")
    return plaintxt

def expand_input(inp: BitArray) -> BitArray(length=6):
    # b1 b2 b3 b4 -> b1 b4 b3 b2 b4 b1
    inp_4 = BitArray(length=4)
    if len(inp) <= 4:
        if len(inp) < 4:
            # fill with leading zeroes
            amount_of_leading_zeroes = 4 - len(inp)
            inp_4.overwrite(inp, amount_of_leading_zeroes)
        elif len(inp) == 4:
            inp_4 = inp
        result = pack("bool=b1, bool=b4, bool=b3, bool=b2, bool=b4, bool=b1", b1=inp_4[0], b2=inp_4[1], b3=inp_4[2], b4=inp_4[3])
        return result
    else: raise ValueError("Length of Input BitArray has to be between 0 and 4")

def xor(expin: BitArray, round_key: BitArray) -> BitArray:
    if len(expin) == len(round_key):
        xor = BitArray()
        i = 0
        while i < len(expin):
            if (expin[i] and round_key[i]): #both 1
                xor.append('0b0')
            elif (expin[i] and not round_key[i]): #expin 1 rndkey 0
                xor.append('0b1')
            elif (not expin[i] and round_key[i]): #expin 0 rndkey 1
                xor.append('0b1')
            elif (not expin[i] and not round_key[i]): # both 0
                xor.append('0b0')
            i += 1
        return xor
    else: raise ValueError("expin and round_key need to be of the same length!")

def s_box(xorin: BitArray) -> BitArray:
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

def mini_des_step(round_input: BitArray(length=4), round_key: BitArray(length=6)) -> BitArray(length=4):
    # expand input from 4 to 6 bits
    expin = expand_input(round_input)
    # XOR with key
    xorin = xor(expin, round_key)
    # Feed into S-Boxes (6bit -> 4bit)
    sboxd = s_box(xorin)
    # return the cyphertext for this round
    return sboxd

# runs all n rounds of mini-des for one textblock(8 bit) with key (n *6 bit)
# 8bit TEXT; 
def do_block_rounds(cleartext_block: BitArray(), sym_block_key: BitArray(), rounds: int) -> BitArray:
    # rounds = 2 # like in Krypt12.mp4

    rnd_keys = []

    # sym_block_key would be 12 bit for 2 rounds
    #                        18 bit for 3
    # etc.
    # Problem: Key (not block_key) cannot be infinite, FIXME: look for better way of getting block key
    for r in range(rounds): # split sym_block_key into smaller round_keys
        if ( len(sym_block_key) / 6 ) == rounds: # key can be split into exactly n (amount of rounds) round_keys with length 6
            rnd_keys.append(sym_block_key[(r*6):(r*6+6)])
        else: raise ValueError("block_key needs to be of length 6n with n as amount of rounds (currently 2)")

    #cleartext block has to be 8 bits
    if len(cleartext_block) == 8:
        next_left = cleartext_block[0:4]
        next_right = cleartext_block[4:8] # setup for first round
        for r in range(rounds): # do rounds
            # split cleartext_block into left an right half (4bit)
            left = next_left
            right = next_right
            next_left = right # put current right into next left block
            # next right block is ( left XOR minides(right,key_n) )
            next_right = xor(left, mini_des_step(right, rnd_keys[r]))

        final_left = next_left
        final_right = next_right

        cyphertext_block = BitArray()
        cyphertext_block.append(final_left)
        cyphertext_block.append(final_right)

        return cyphertext_block

    else:
        raise ValueError("cleartext_block needs to be exactly 8 bits.")

def encrypt_text(plaintxt: str, symmetric_key: BitArray()) -> BitArray():
    plain_blocks = slice_plaintext(plaintxt)
    # what to do with key? length of key? figure this out first.

if __name__ == "__main__":
    print("This file should not be run as a script, only imported as a module!")
    encrypt_text("Hallo! Hier ist ein String mit ü und ä!", BitArray('0b0'))