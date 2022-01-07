# coding=utf-8
import mini_des

if __name__ == "__main__":

    n = 8 # number of threads

    #setup data
    plaintext = "Dies ist eine wirklich wichtige und geheime Nachricht, die nichtmal die NSA sehen darf! (Auch wenn die NSA sicherlich einfach an die Lösung kommt....) Denn der crazy stuff ist wirklich sehr stark... saduiztgbfgbfvvawiuzfthiav7oww  zf87waezf i87qw6e6eatzt zf bfb98qwezf iuwrazzgfwisdaf b86awegf kwzduagfwiuarzbf uizsadbf987q234hf iwqh foiqjfoiuewrhoghke0gi3298zti7erzt234q9583745765873462873658734658732465782346593457569238dsfjbngvsdkjvnbsdkfjhgsdklfjgn                         uwzerfur otiwero9 8tzu2n0983u590t09h"
    key = mini_des.generate_key("hier-könnte-ihr-passwort-stehen!denn-es-ist-recht-lang-lulundlol27364823")

    #run encryption
    enc = mini_des.encrypt_text(plaintext, key, n)
    print("======ENCRYPTED MESSAGE======")
    print(enc)
    print(len(enc))

    #run decryption
    dec = mini_des.decrypt_text(enc, key, n)
    print("======DECRYPTED MESSAGE======")
    print(dec)
    print("\n\n")
    if (plaintext == dec):
        print("decryption successful.")
    else: print("decryption FAILED.")
