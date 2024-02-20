# CsCyb23004 - Dimitris Vasileiadis
# text file enconding: UTF-8 without BOM

import random
import string


# Δημιουργία τυχαίου κλειδιού *keyLength* χαρακτήρων
def GenerateRandomKey(keyLength):
    random.seed()

    # χρησιμοποιούνται μόνο ascii γράμματα κεφαλαία και μικρά και αριθμητικά ψηφία
    # για ευκολία στην εμφάνιση και την εκτύπωση
    chars = string.ascii_letters + string.digits
    key = [ord(random.choice(chars)) for _ in range(keyLength)]
    # εναλλακτικά μπορούν να χρησιμοποιηθούν οποιηδήποτε ascii χαρακτήρες
    # key = random.sample(range(256), keyLength)
    return key


# Δημιουργεί ένα τυχαίο κείμενο μήκους length χαρακτήρων
# που αποτελείται αποκλειστικά από τα ψηφία "0"-"9"
def GenerateRandomDecimalString(length):
    random.seed()
    # We limit values to printable characters and digits for convenient display
    chars = string.digits
    key = [random.choice(chars) for _ in range(length)]
    # key = random.sample(range(256), length)
    return key


# Επιστρέφει τα bit 7-4 (MSN - most significant nibble) ενός byte σαν αριθμό
def LeftNibble(str):
    return int((BinaryToNumber(str) & 0b11110000)) 


# Επιστρέφει το bit 3-0 (LSN - least significant nibble) ενός byte σαν αριθμό
def RightNibble(str):
    return int((BinaryToNumber(str) & 0b00001111))


# Μετατροπή αριθμού (ascii code) σε binary string, με μήκος length (default 8)
def NumberToBinary(charcode, length=8):
    return bin(charcode)[2:].zfill(length)


# Μετατροπή binary string σε αριθμό (ascii code)
def BinaryToNumber(binaryString):
    return int(binaryString.strip(), 2)


# Σπάσιμο ενός string σε πίνακα από strings το καθένα *length* χαρακτήρων
def SplitStringByLength(string, length):
    result = []
    for i in range(0, len(string), length):
        result.append(string[i:i+length])
    return result


# Σπάσιμο ενός string σε πίνακα από strings όπου εμφανίζεται το ' '
def SplitStringByDelimiter(string, delimiter):
    return string.split(delimiter)


# Κωδικοποίηση με XOR του κειμένου plaintext με το κλειδί key
# Επιστρέφει το cipher σε binary μορφή (με ενδιάμεσα κενά για ευκολία στην εμφάνιση) 
def Encrypt(plaintext, key):
    ciphertext = ""
    for i in range(len(plaintext)):
        ch = ord(plaintext[i]) ^ key[i]
        ciphertext += NumberToBinary(ch)
        ciphertext += " "
    return ciphertext.strip()


# Κάνει το κείμενο εκτυπώσιμο αντικαθιστώντας τους μή εκτυπώσιμους χαρακτήρες με 😵
def MakeTextPrintable(nonPrintableText):
    printableText = ''
    for ch in nonPrintableText:
        if ch.isprintable():
            printableText += ch
        else:
            printableText += '😵'
    return printableText
