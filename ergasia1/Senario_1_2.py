# CsCyb23004 - Dimitris Vasileiadis
# text file enconding: UTF-8 without BOM

from binaryfunc import Encrypt, GenerateRandomDecimalString, GenerateRandomKey, SplitStringByDelimiter, MakeTextPrintable
from myfunctions2 import FindAllKeysLeftNibble, FindAllKeysAndMessageCharacters, PrintKeyCombinations

# Επιτρέπονται μόνο δεκαδικά ψηφία
ValidDigits = '0123456789'


#############################################################################################
#
# Αρχικοποίηση παραμέτρων της επίθεσης
#
#############################################################################################

# -------------------------------------------------------------------------------------------
# Δημιουργία τυχαίων μηνυμάτων, δημιουργία τυχαίου OTP, κωδικοποίησή τους και σπάσιμο των
# ciphertexts σε ομάδες των 8 χαρακτήρων που αναπαριστούν την binary μορφή του κάθε byte του
# αντίστοιχου ciphertext για να μπορούμε να το επεξεργαστούμε
# -------------------------------------------------------------------------------------------


# Ορίζουμε πόσο μεγάλα θέλουμε να είναι τα plaintexts
# Για να κάνουμε την επίθεση και να δούμε πόσο πιο σίγουροι μπορούμε να γίνουμε για την εύρεση
# κάποιου κλειδιού θέλουμε τα 3 τουλάχιστον πρώτα plaintexts να έχουν το ίδιο μέγεθος, ώστε
# να φανεί η διαφορά όταν συγκρίνουμε τα αποτελέσματα της επίθεσης ανάμεσα σε 2 ciphers από
# τα αποτελέσματα της επίθεσης όταν έχουμε 3 ciphers.
# Το 4ο plaintext το θέλουμε να έχει μεγαλύτερο μέγεθος ώστε να δούμε τη διαφορά ανάμεσα 
# σε 3 ciphers και σε 4 ciphers που έχουν διαφορετικό μέγεθος.

plain_text_lenghts = [2, 2, 2, 6]
#plain_text_lenghts = [6, 6, 6, 5]

# Δημιουργία τυχαίων Plaintexts αποτελούμενα μόνο από αριθμητικούς χαρακτήρες
P1 = GenerateRandomDecimalString(plain_text_lenghts[0]) 
P2 = GenerateRandomDecimalString(plain_text_lenghts[1])
P3 = GenerateRandomDecimalString(plain_text_lenghts[2])
P4 = GenerateRandomDecimalString(plain_text_lenghts[3])

# Δημιουργία τυχαίου κλειδιού OTP ικανού μεγέθους να κωδικοποιήσει όλα τα plaintexts
encryptionKey = GenerateRandomKey(max(len(P1), len(P2), len(P3), len(P4)))

# Δημιουργία των ciphertexts με (κακή) επαναχρησιμοποίηση του κλειδιού πολλές φορές.
Cipher1 = Encrypt(P1, encryptionKey)
Cipher2 = Encrypt(P2, encryptionKey)
Cipher3 = Encrypt(P3, encryptionKey)
Cipher4 = Encrypt(P4, encryptionKey)

# Πλέον τα plainttexts τα θεωρούμε άγνωστα και θα προσπαθήσουμε εάν μπορούμε να τα βρούμε,
# όπως και τα αντίστοιχα κλειδιά που τα κωδικοποιούν στα ciphertexts που έχουμε.
# για την άσκηση δεν θα διαγράψουμε τα περιεχόμενα των μεταβλητών προκειμένου να τα εμφανίζουμε
# και να δούμε εάν μπορούμε να τα βρούμε.

# P1 = ''
# P2 = ''
# P3 = ''
# P4 = ''


# -------------------------------------------------------------------------------------------
# Εναλλακτικά, χρήση συγκεκριμένων ciphertexts που προήλθαν από plaintexts
# κρυπτογραφημένα με το ίδιο κλειδί OTP
# -------------------------------------------------------------------------------------------

# Cipher1 = '01111111 01110101'
# Cipher2 = '01110010 01111100'
# Cipher3 = '01111000 01111001'
# Cipher4 = '01111010 01111011 01000011 01111000 01101010 01111010'

C1 = SplitStringByDelimiter(Cipher1, ' ')
C2 = SplitStringByDelimiter(Cipher2, ' ')
C3 = SplitStringByDelimiter(Cipher3, ' ')
C4 = SplitStringByDelimiter(Cipher4, ' ')


#############################################################################################
#
# Εκτέλεση της επίθεσης για 2 cipherTexts
#
#############################################################################################

print('P1 = ' + MakeTextPrintable(P1))
print('P2 = ' + MakeTextPrintable(P2))

print('C1 = ' + Cipher1)
print('C2 = ' + Cipher2)

CiphersToCheck = [C1,C2]

KeysLeftNibble = FindAllKeysLeftNibble(CiphersToCheck)

possibleKeySets, possibleMessageCharacters = FindAllKeysAndMessageCharacters(ValidDigits, KeysLeftNibble, CiphersToCheck)

PrintKeyCombinations(possibleKeySets, CiphersToCheck)

print()
print('------------------------------------------------------------------------------------------------')
print()

#############################################################################################
#
# Εκτέλεση της επίθεσης για 3 cipherTexts
#
#############################################################################################

print('P1 = ' + MakeTextPrintable(P1))
print('P2 = ' + MakeTextPrintable(P2))
print('P3 = ' + MakeTextPrintable(P3))

print('C1 = ' + Cipher1)
print('C2 = ' + Cipher2)
print('C3 = ' + Cipher3)

CiphersToCheck = [C1,C2,C3]

KeysLeftNibble = FindAllKeysLeftNibble(CiphersToCheck)

possibleKeySets, possibleMessageCharacters = FindAllKeysAndMessageCharacters(ValidDigits, KeysLeftNibble, CiphersToCheck)

PrintKeyCombinations(possibleKeySets, CiphersToCheck)

print()
print('------------------------------------------------------------------------------------------------')
print()

#############################################################################################
#
# Εκτέλεση της επίθεσης για 4 cipherTexts
#
#############################################################################################

print('P1 = ' + MakeTextPrintable(P1))
print('P2 = ' + MakeTextPrintable(P2))
print('P3 = ' + MakeTextPrintable(P3))
print('P4 = ' + MakeTextPrintable(P4))

print('C1 = ' + Cipher1)
print('C2 = ' + Cipher2)
print('C3 = ' + Cipher3)
print('C4 = ' + Cipher4)

CiphersToCheck = [C1,C2,C3,C4]

KeysLeftNibble = FindAllKeysLeftNibble(CiphersToCheck)

possibleKeySets, possibleMessageCharacters = FindAllKeysAndMessageCharacters(ValidDigits, KeysLeftNibble, CiphersToCheck)

PrintKeyCombinations(possibleKeySets, CiphersToCheck)
