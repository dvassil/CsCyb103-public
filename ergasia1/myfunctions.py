# CsCyb23004 - Dimitris Vasileiadis
# text file enconding: UTF-8 without BOM

from binaryfunc import BinaryToNumber, NumberToBinary, SplitStringByLength


# Επιστρέφει το κλειδί σε binary μορφή (με ενδιάμεσα κενά για ευκολία στην εμφάνιση)
def ShowKey(key):
    keytext = ''.join([NumberToBinary(i) + ' ' for i in key])
    return keytext


# Επιστρέφει το κλειδί σαν string
def ShowKeyAsString(key):
    keytext = ''.join([chr(i) for i in key])
    return keytext


# Εξάγει το κλειδί, χρησιμοποιώντας τα γνωστά plaintext1 και ciphertext1,
# που χρησιμοποιήθηκε για την κρυπτογράφηση του plaintext1
def ExportKey(plaintext1, ciphertext1):
    # Αφαίρεση κενών από το cipher ώστε να μείνουν μόνο τα binary δεδομένα
    ciphertext1 = ciphertext1.replace(' ' ,'')

    # Σπάσιμο του cipher1 σε binary strings και μετατροπή τους σε αριθμούς
    ciphertext1List = SplitStringByLength(ciphertext1.strip(), 8)
    cipherList1 = [BinaryToNumber(xi) for xi in ciphertext1List]

    # Εύρεση του κλειδιού αξιποιώντας το plaintext1 και το cipher1
    key = []
    for pi, ci  in zip(plaintext1, cipherList1):
        key.append(ord(pi) ^ ci)

    return key


# Αποκωδικοποίηση του ciphertext2 αξιποιώντας το plaintext1 και το cipher1
# Επιστρέφει το plaintext2 που αντιστοιχεί στο cipher2 σαν string
def Decrypt(plaintext1, ciphertext1, ciphertext2):
    # Αφαίρεση κενών από το cipher ώστε να μείνουν μόνο τα binary δεδομένα
    ciphertext1 = ciphertext1.replace(' ' ,'')
    ciphertext2 = ciphertext2.replace(' ' ,'')

    # Σπάσιμο του cipher1 σε binary strings και μετατροπή τους σε αριθμούς
    ciphertext1List = SplitStringByLength(ciphertext1.strip(), 8)
    cipherList1 = [BinaryToNumber(xi) for xi in ciphertext1List]

    # Σπάσιμο του cipher2 σε binary strings και μετατροπή τους σε αριθμούς
    ciphertext2List = SplitStringByLength(ciphertext2.strip(), 8)
    cipherList2 = [BinaryToNumber(xi) for xi in ciphertext2List]

    # Αποκωδικοποίηση του cipher2 αξιποιώντας το plaintext1 και το cipher1
    decrypted_text = ''
    for pi, ci, ci2 in zip(plaintext1, cipherList1, cipherList2):
        ch = ord(pi) ^ ci ^ ci2
        decrypted_text = decrypted_text + chr(ch)

    return decrypted_text


def EncodedTextAsString(cipher, startPosition):
    # Αφαίρεση κενών από το cipher ώστε να μείνουν μόνο τα binary δεδομένα
    cipher = cipher.replace(' ' ,'')
    ciphertextList = SplitStringByLength(cipher.strip(), 8)
    cipherList = [BinaryToNumber(xi) for xi in ciphertextList]
    encodedText = ''.join([chr(x) for x in cipherList])

    #ignore first characters until startPosition
    encodedText = encodedText[startPosition:]
    return encodedText
