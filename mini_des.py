from bitstring import BitArray, pack as __pack
from multiprocessing import Pool as __Pool
from numpy.lib.shape_base import array_split as __array_split

def __slice_plaintext(plaintxt: str) -> list(BitArray()): # splits given string into list of BitArrays each of length 8.
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

def __unslice_plaintext(plainslices: list) -> str: # reverses slice_plaintext: uses list of 8-bit long BitArrays to reconstruct unicode strings
    concat = BitArray()
    for slice in plainslices:
        concat.append(slice)
    encoded_bytes = concat.bytes
    plaintxt = encoded_bytes.decode("utf-8","ignore")
    return plaintxt

def __slice_cyphertext(cyphertxt: str) -> list(BitArray()):
    slices = []
    if len(cyphertxt) % 2 == 0:
        times = len(cyphertxt) // 2
        for r in range(0, 2 * times, 2):
            nextpair = cyphertxt[r:r+2]
            slices.append(BitArray(hex=nextpair))
        return slices
    else: raise ValueError("cyphertext has to have a length divisible by 2!")

def __unslice_cyphertext(cypherslices: list) -> str: # reverses slice_cyphertext: uses list of 8-bit long BitArrays to reconstruct unicode strings
    concat = BitArray()
    for slice in cypherslices:
        concat.append(slice)
    encoded_str = str(concat.hex)
    return encoded_str

def __expand_input(inp: BitArray) -> BitArray(length=6):
    # b1 b2 b3 b4 -> b1 b4 b3 b2 b4 b1
    inp_4 = BitArray(length=4)
    if len(inp) <= 4:
        if len(inp) < 4:
            # fill with leading zeroes
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
            if (a[i] and b[i]): #both 1
                xor.append('0b0')
            elif (a[i] and not b[i]): #expin 1 rndkey 0
                xor.append('0b1')
            elif (not a[i] and b[i]): #expin 0 rndkey 1
                xor.append('0b1')
            elif (not a[i] and not b[i]): # both 0
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
    # expand input from 4 to 6 bits
    expin = __expand_input(round_input)
    # XOR with key
    xorin = __xor(expin, round_key)
    # Feed into S-Boxes (6bit -> 4bit)
    sboxd = __s_box(xorin)
    # return the cyphertext for this round
    return sboxd

def __encrypt_blocks_thread(cleartext_blocks: list(BitArray()), sym_block_key: BitArray()) -> BitArray: # runs all n rounds of mini-des for one textblock(8 bit) with key (n *6 bit)
    cyphertext_result = BitArray()
    todo = len(cleartext_blocks)
    done = 0
    for cleartext_block in cleartext_blocks:
        if (done == 0): print(".",end="",flush=True)
        elif (done == 1*(todo//4)): print("-",end="",flush=True)
        elif (done == 2*(todo//4)): print("~",end="",flush=True)
        elif (done == 3*(todo//4)): print("+",end="",flush=True)
        elif (done+1 == todo): print("#",end="",flush=True)
        if (len(sym_block_key) % 6 == 0):

            # TODO: rounds = 2 # like in Krypt12.mp4? Or something else? Also: key-length...
            # Waiting for Matthes to respond
            rounds = len(sym_block_key) // 6
            rnd_keys = []

            # sym_block_key would be 12 bit for 2 rounds, 18 bit for 3
            for r in range(rounds): # split sym_block_key into smaller round_keys
                rnd_keys.append(sym_block_key[(r*6):(r*6+6)])

            #cleartext block has to be 8 bits
            if len(cleartext_block) == 8:
                next_left = cleartext_block[0:4]
                next_right = cleartext_block[4:8] # setup for first round
                for r in range(rounds): # do rounds
                    # split cleartext_block into left an right half (4bit)
                    left = next_left
                    right = next_right
                    next_left = right # put current right into next left block
                    # next right block is ( left __xor minides(right,key_n) )
                    next_right = __xor(left, __mini_des_step(right, rnd_keys[r]))

                final_left = next_left
                final_right = next_right
                
                cyphertext_result.append(final_left)
                cyphertext_result.append(final_right)
            else: raise ValueError("cleartxt_block needs to be of length 8 Bit")
        else: raise ValueError("block_key needs to be of length 6n with n as amount of rounds (currently 2)")
        done += 1
    return cyphertext_result

def __decrypt_blocks_thread(cyphertext_blocks: list(BitArray()), sym_block_key: BitArray()) -> BitArray: # runs all n rounds of mini-des for one textblock(8 bit) with key (n *6 bit)
    cleartext_result = BitArray()
    todo = len(cyphertext_blocks)
    done = 0
    for cyphertext_block in cyphertext_blocks:
        if (done == 0): print(".",end="",flush=True)
        elif (done == 1*(todo//4)): print("-",end="",flush=True)
        elif (done == 2*(todo//4)): print("~",end="",flush=True)
        elif (done == 3*(todo//4)): print("+",end="",flush=True)
        elif (done+1 == todo): print("#",end="",flush=True)
        if (len(sym_block_key) % 6 == 0):

            #TODO: rounds = 2 # like in Krypt12.mp4? waiting for Matthes answer to email
            rounds = len(sym_block_key) // 6 # rounds depends on keylen 
            rnd_keys = []

            # sym_block_key would be 12 bit for 2 rounds 18 bit for 3
            for r in range(rounds): # split sym_block_key into smaller round_keys
                if ( len(sym_block_key) / 6 ) == rounds: # key can be split into exactly n (amount of rounds) round_keys with length 6
                    rnd_keys.append(sym_block_key[(r*6):(r*6+6)])
                else: raise ValueError("block_key needs to be of length 6n with n as amount of rounds (currently 2)")

            #cyphertext block has to be 8 bits
            if len(cyphertext_block) == 8:
                bot_left = cyphertext_block[0:4]
                bot_right = cyphertext_block[4:8]
                for r in range(rounds-1, -1, -1): # example: rounds=3-> r : 2,1,0
                    top_right = bot_left
                    top_left = __xor(bot_right,__mini_des_step(top_right, rnd_keys[r]))
                    bot_left = top_left
                    bot_right = top_right
                
                final_left = bot_left
                final_right = bot_right

                cleartext_result.append(bot_left)
                cleartext_result.append(bot_right)     
            else: raise ValueError("cyphertext_block needs to be exactly 8 bits.")
        else: raise ValueError("block_key needs to be of length 6n with n as amount of rounds (currently 2)")
        done += 1
    return cleartext_result

def __run_encryption_threads(plain_blocks: list(BitArray()), symmetric_key: BitArray(), n: int) -> BitArray: # spawns n new processes that encrypts all the blocks and returns the encrypted Block-List
    print("Using "+str(n)+" threads. Be patient!")
    crypt_blocks = []
    thread_sized_plain_chunks = __array_split(plain_blocks, n)
    p = __Pool(n)
    args = []
    for i in range(n):
        args.append([thread_sized_plain_chunks[i], symmetric_key])
    #multithread encryption
    print("Encrypting",end="",flush=True)
    crypt_blocks = p.starmap(__encrypt_blocks_thread, tuple(args))
    print("")
    return crypt_blocks

def __run_decryption_threads(cypher_blocks: list(BitArray()), symmetric_key: BitArray(), n: int) -> BitArray(): # spawns n new processes that decrypts all the blocks and returns the encrypted Block-List
    print("Using "+str(n)+" threads. Be patient!")
    decrypt_blocks = []
    thread_sized_encrypted_chunks = __array_split(cypher_blocks, n)
    p = __Pool(n)
    args = []
    for i in range(n):
        args.append([thread_sized_encrypted_chunks[i], symmetric_key])
    #multithread decryption
    print("Decrypting",end="",flush=True)
    decrypt_blocks = p.starmap(__decrypt_blocks_thread, tuple(args))
    print("")
    return decrypt_blocks

def encrypt_text(plaintxt: str, symmetric_key: BitArray(), threads: int) -> str:
    plain_blocks = __slice_plaintext(plaintxt)
    # Number of Rounds depends on key length. Only keys with n*6 Bit are allowed, else fill up with zeroes
    repeat = True
    key_isgood = False
    while repeat: # Test if key is okay or needs to be filled to specific size with zeroes
        if (len(symmetric_key) % 6 == 0): # key len is multiple of 6, so n*6 requirement is met
            repeat = False
            key_isgood = True
        else: # key len is too short, appending zeroes to get len multiple of 6
            diff = 6 - len(symmetric_key) % 6
            zeroes = BitArray(diff * '0b0')
            symmetric_key.append(zeroes)
    if key_isgood:
        crypt_blocks = __run_encryption_threads(plain_blocks, symmetric_key, threads)
    else: raise ValueError("Key is not good! Investigate") #TODO: besser formulieren
    print("Finished encrypting.")
    return __unslice_cyphertext(crypt_blocks)

def decrypt_text(cyphertxt: str, symmetric_key: BitArray(), threads: int) -> str:
    cypher_blocks = __slice_cyphertext(cyphertxt)
    # Number of rounds depends on key length. Only keys with n*6 Bit are allowed, else fill up with zeroes
    repeat = True
    key_isgood = False
    while repeat:
        if (len(symmetric_key) % 6 == 0 and len(symmetric_key) > 6): # key len is multiple of 6, so n*6 requirement is met
            repeat = False
            key_isgood = True
        else: # key len is too short, appending zeroes to get len multiple of 6
            diff = 6 - len(symmetric_key) % 6
            zeroes = BitArray(diff * '0b0')
            symmetric_key.append(zeroes)
    if key_isgood:
        decrypt_blocks = __run_decryption_threads(cypher_blocks, symmetric_key, threads)
    else: raise ValueError("Key is not good! Investigate") #TODO: besser formulieren
    print("Finished decrypting.")
    return __unslice_plaintext(decrypt_blocks)

def generate_key(passphrase: str) -> BitArray():
    p_bytes = passphrase.encode("utf-8","strict")
    key = BitArray(bytes=p_bytes)
    return key

if __name__ == "__main__":
    print("This file should not be run as a script, only imported as a module!")