# CsCyb23004 - Dimitris Vasileiadis
# text file enconding: UTF-8 without BOM

from binaryfunc import Encrypt, GenerateRandomKey, MakeTextPrintable
from myfunctions import Decrypt, EncodedTextAsString, ExportKey, ShowKeyAsString


#############################################################################################
#
# Αρχικοποίηση παραμέτρων της επίθεσης
#
#############################################################################################

# ----------------------------------------------------------------
# We can use this code to generate random keys and try to encode
# the known plaintext 1 to get the known cipher 1
# also we generate the other known ciphers
# the plaintexts are supposed to be unknown
# ----------------------------------------------------------------

plainText1        = "SIMPLE KNOWN MESSAGE"
plainText2        = "What AM I DOING here"
plainText2smaller = "Thought is free"
plainText2bigger  = "What is past is prologue"


encryptionKeyLength = max([
    len(plainText1),
    len(plainText2),
    len(plainText2smaller),
    len(plainText2bigger)
    ])

# Generate a key long enough
encryptionKey = GenerateRandomKey(encryptionKeyLength)

cipher1           = Encrypt(plainText1, encryptionKey)
cipher2           = Encrypt(plainText2, encryptionKey)
cipher2smaller    = Encrypt(plainText2smaller, encryptionKey)
cipher2bigger     = Encrypt(plainText2bigger, encryptionKey)

plainText2        = ""
plainText2smaller = ""
plainText2bigger  = ""
# encryptionKey     = ''


# ----------------------------------------------------------------
# Now we have a known plainText1
#             a known cipher1
#         and a known cipher2
#         but unknown encryption key
#         and unknown plainText2
#         and unknown plainText2smaller
#         and unknown plainText2bigger
#         and unknown encryption key

print("Plain Text  1         - " + plainText1)
print("Cipher Text 1         - " + cipher1)
print("Cipher Text 2         - " + cipher2)
print("Cipher Text 2 smaller - " + cipher2smaller)
print("Cipher Text 2 bigger  - " + cipher2bigger)
print()

extractedKey = ExportKey(plainText1, cipher1)
print("Encryption key used       : " + ShowKeyAsString(encryptionKey))
print("Extracted key from attack : " + ShowKeyAsString(extractedKey))
print()

#############################################################################################
#
# Εκτέλεση της επίθεσης
#
#############################################################################################

plainText2        = Decrypt(plainText1, cipher1, cipher2)
plainText2smaller = Decrypt(plainText1, cipher1, cipher2smaller)
plainText2bigger  = Decrypt(plainText1, cipher1, cipher2bigger)

remainingText2bigger = EncodedTextAsString(cipher2bigger, len(plainText2bigger))
remainingText2biggerPrintable = MakeTextPrintable(remainingText2bigger)

if (remainingText2biggerPrintable != remainingText2bigger):
    remainingText2biggerPrintable += "            (😵 represent non printable character)"

print("Decrypted Plain Text  2         - " + plainText2)
print("Decrypted Plain Text  2 smaller - " + plainText2smaller)
print("Decrypted Plain Text  2 bigger  - " + plainText2bigger)
print("          Remaining   2 bigger  - " + remainingText2biggerPrintable)
