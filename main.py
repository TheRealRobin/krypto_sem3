import mini_des

#setup data
plaintext = "Hallo Welt, díês ìst ein Test-PlainText mit seltsamen Zeichen ß♠☼Ö保育園ほいくえんにらえた。😀😀"
key = mini_des.generate_key("KryptografischerSchlüssel")

#run encryption
enc = mini_des.encrypt_text(plaintext, key)
print(enc)

#run decryption
dec = mini_des.decrypt_text(enc, key)
if (plaintext == dec):
    print("decryption successful.")
else: print("decryption FAILED.")