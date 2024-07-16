from Crypto.PublicKey import RSA
import os
import random
import string
import pwinput
from Crypto.Cipher import PKCS1_OAEP
import pyperclip


cwd = os.getcwd()

char_list = list(string.ascii_uppercase) + list(string.ascii_lowercase) + list(string.digits) + list(string.punctuation)


def clear():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")
    print(
        """
        ____  _________ ____________  ______  ______
       / __ \/  _/ ___// ____/ __ \ \/ / __ \/_  __/
      / / / // / \__ \/ /   / /_/ /\  / /_/ / / /   
     / /_/ // / ___/ / /___/ _, _/ / / ____/ / /    
    /_____/___//____/\____/_/ |_| /_/_/     /_/    


       """)
    

clear()

def display_options():
    print("Main Menu \n1: Generate new RSA keypair \n2: Verify someones identity \n3: Get your identity verified \n4: HOW TO GUIDE \n5: Clear screen")
display_options()
keys_path = os.path.join(cwd , "Keys")
your_keys = os.path.join(keys_path , "Mine")

while True:
    private_key_path = os.path.join(your_keys  , "rsa_private.oss")
    public_key_path = os.path.join(your_keys  , "rsa_public.oss")
    option = int(input("Enter your option: ").strip())
    
    if option == 1:
        private_key = RSA.generate(4096)
        password_for_encryption = pwinput.pwinput("Enter a password to encrypt your private key: " , mask="*").strip()
        encrypted_key = private_key.export_key(passphrase=password_for_encryption, pkcs=8, protection="scryptAndAES128-CBC", prot_params={'iteration_count':131072})
        f = open(private_key_path , "w")
        f.write(encrypted_key.decode())
        f.close()
        

        public_key = private_key.publickey().export_key()

        f = open(public_key_path , "w")
        f.write(public_key.decode())
        f.close()


        del private_key
        del encrypted_key
        del public_key

        print("CREATED RSA KEY PAIR")

    elif option == 2:
        username_to_verify = input("Enter the username you want to verify: ").strip()
        key_path = os.path.join(keys_path , username_to_verify , "rsa_public.oss")

        other_guy_key = RSA.import_key(open(key_path).read())

        random_code = ""
        random_stuff = random.choices(char_list, k=128)
        for i in random_stuff:
            random_code = random_code + i
        
        cipher_rsa = PKCS1_OAEP.new(other_guy_key)
        encrypted_code = cipher_rsa.encrypt(random_code.encode())

        print(f"Challenge code for {username_to_verify} has been generated")
        f = open(f"challenge_code_{username_to_verify}.oss" , "wb")
        f.write(encrypted_code)
        f.close()


        response_code = input("Enter response code: ").strip()
        if response_code == random_code:
            print("VERIFIED")
        else:
            print("INVALID RESPONSE CODE | MIGHT BE A FAKER | PROCEED WITH CAUTION")

    elif option == 3:

        code_to_decrypt = input("Enter the challenge code file name to verify: ").strip()
        pass_code = pwinput.pwinput("Enter your password to decrypt your private key: " , mask = "*").strip()
        key_path = os.path.join(your_keys , "rsa_private.oss")

        f = open(code_to_decrypt , "rb")
        code_to_decrypt = f.read()
        f.close()

        with open(key_path , "rb") as f:
            key_data = f.read()
            rsa_priv_key = RSA.import_key(key_data, passphrase=pass_code)
            rsa_priv_cipher = PKCS1_OAEP.new(rsa_priv_key)

        print(type(code_to_decrypt))
        decrypted_key = rsa_priv_cipher.decrypt(code_to_decrypt)

        print("RESPONSE CODE GENERATED")
        print(decrypted_key.decode())

    elif option == 4:
        clear()
        print("===HOW TO USE DISCRYPT===")
        print("Step 1 --> Generate your RSA private-public key pair \nStep 2 --> Make your RSA public key, well, public. A user can only verify your identity if he has your public key. \nENSURE YOUR PRIVATE KEY AND THE PASSWORD YOU USED TO MAKE IT NEVER LEAKS. IT CAN BE USED TO STEAL YOUR IDENTITY \nStep 3 --> When you get disabled, the other guy can generate a challenge code file, which you can then use to verify your identity.\nStep 4 --> You can save a persons RSA Public key in the keys folder with their username as folder name in order to verify their identity in the future")
        display_options()


    elif option == 5:
        clear()
        display_options()









