import cryptography
import base64
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Dont touch, these are encryption variables
salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
cipher_suite = None

#Static variables
version = "0.1.1"

def main():
    setNewPassphrase()
    running = True
    while(running) :
        opCode = 0
        cmd = input(">>>").strip()
        #User input parser
        if cmd == "\q":
            running = closeout()
        elif cmd == "\\h" or cmd == "-h" or cmd == "--help" :
            running = help()
        elif cmd == "\\v" or cmd == "-v" or cmd == "--version" :
            running = about()
        elif cmd == "\\c" or cmd == "--conn" or cmd == "--testConnection" :
            running = testConnection() #unimplemented
        elif cmd == "\\n" or cmd == "-n" or cmd == "--newPhrase":
            running = setNewPassphrase()
        elif cmd == "\\d" or cmd == "-d" or cmd == "--decrypt":
            running = decryptMessage()
        else:
            running = sendAMessage(cmd)

def sendAMessage(text_msg):
    byte_msg = bytes(text_msg, "ascii")
    cipher_text = cipher_suite.encrypt(byte_msg)
    plain_text = cipher_suite.decrypt(cipher_text)
    print("Sample: " + plain_text.decode("utf-8"))
    print("Result: " + cipher_text.decode("utf-8"))
    return True

def decryptMessage():
    enc_msg = input("Enter your encrypted message\n>>>")
    byte_msg = bytes(enc_msg, "ascii")
    plain_text = cipher_suite.decrypt(byte_msg)
    print("Result: " + plain_text.decode("utf-8"))
    return True

def closeout():
    print("Goodbye")
    sys.exit(0)
    return False

def about():
    print("_-WHISPER-_")
    print("v", version)
    print("author: Turner Bowling - June 7, 2020")
    return True

def help():
    print("_-WHISPER-_")
    print("User Guide:")
    print("Enter a command in the prompt, which appears as: \">>>\"")
    print("Valid commands are:")
    print("\\q\t\t\t\t\tQuits the program")
    print("\\h\t-h\t--help\t\t\tDisplays this guide")
    print("\\v\t-v\t--version\t\tDisplays information on this application")
    print("\\c\t--conn\t--testConnection\tTests the connection to the server and displays results")
    print("\\n\t-n\t--newPhrase\t\tAllows the user to enter a new passphrase for encryption")
    print("Anything else will be interpreted as a message to be sent to the server")
    return True

def setNewPassphrase():
    global cipher_suite
    text_seed = input("Please enter your passphrase\n>>>")
    byte_seed = bytes(text_seed, "ascii")
    key = base64.urlsafe_b64encode(kdf.derive(byte_seed))
    cipher_suite = Fernet(key)
    print("<<PASSPHRASE SET SUCCESSFULLY")
    return True

# If makeRsaKeys.py is run (instead of imported as a module) call
# the main() function.
if __name__ == '__main__':
	main()
