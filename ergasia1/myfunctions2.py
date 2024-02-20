# CsCyb23004 - Dimitris Vasileiadis
# text file enconding: UTF-8 without BOM

import random
import string
import sys
from binaryfunc import *

__keys = []
__CiphersToCheck = []
__ValidDigits = []
__KeysLeftNibble = []
__checkCiphers = []


# Επιστρέφει το MSN ενός byte του κλειδιού σαν αριθμό
def FindOneKeyLeftNibble(MessageByte, CipherByte):
    MLN = LeftNibble(MessageByte)
    CLN = LeftNibble(CipherByte)
    KLN = (MLN ^ CLN)
    return KLN


# Επιστρέφει πίνακα με τα left nibbles όλων των bytes του κλειδιού
# Αξιοποιεί τη γνώση πως το αρχικό μήνυμα είναι δεκαδικό ψηφίο οπότε γνωρίζουμε
# πως ο ascii κωδικός είναι της μορφής 0011xxxx
def FindAllKeysLeftNibble(Ciphers):
    klMaxLen = -1
    maxCipher = []
    for cipher in Ciphers:
        klLen = len(cipher)
        if klLen > klMaxLen:
            klMaxLen = klLen
            maxCipher = cipher

    MessageByte = '00110000'
    KLs = [FindOneKeyLeftNibble(MessageByte, Ci) for Ci in maxCipher]
    return KLs


# # Επιστρέφει το MSN ενός byte σαν binary string
# def LeftNibbleAsString(str):
#     num = LeftNibble(str) >> 4
#     return bin(num)[2:].zfill(4)


# # Επιστρέφει το LSN ενός byte σαν binary string
# def RightNibbleAsString(str):
#     num = RightNibble(str)
#     return bin(num)[2:].zfill(4)


# Δοκιμάζουμε όλες τις πιθανές τιμές του κλειδιού (τα 4 δεξιά bits) 
# που βγάζουν το αποδεκτό ψηφίο ('0' - '9') για καθένα από τα ciphers
# Για κάθε αποδεκτό κλειδί που εντοπίζουμε βρίσκουμε τους συνδιασμούς 
# χαρακτήρων που αποκωδικοποιούνται με αυτό το κλειδί από τα ciphers
# Κάθε φορά ελέγχουμε για το byte στη θέση 'byteIndex' των ciphers
# messageCharacters = []
def FindAllKeysAndMessageCharactersAtIndex(byteIndex):
    global __ValidDigits
    global __KeysLeftNibble
    global __checkCiphers

    possibleMessageCharacters = []

    ciphersCount = len(__checkCiphers)

    possible_keys = []
    cipherLengths = [len(c) for c in __checkCiphers]
    messages = []

    # Θα δοκιμάσουμε να δημιουργήσουμε κλειδιά των οποίων η τιμή του left nibble είναι αυτή που έχουμε
    # υπολογίσει και η τιμή του right nibble είναι οποιοσδήποτε συνδυασμός των 4 bit (bits 3-0)
    # Το least significant nibble μπορεί να πάρει τιμές από 0x00 - 0x0F 
    for i in range(0x0F + 1):

        # Συνδιάζουμε την τιμή του most significant nibble που έχουμε υπολογίσει για το byte στη θέση
        # byteIndex με την τιμή i 
        key = __KeysLeftNibble[byteIndex] | i

        # Θεωρούμε αρχικά πως το κλειδί αποκρυπτογραφεί όλα τα ciphers σε αποδεκτούς message χαρακτήρες
        checked = True
        
        Mi_Combinations = []
        # Προσπάθησε να βρείς όλα τα Mi[x] που παράγονται από το Ci[x] XOR key
        for cipherIndex in range(ciphersCount):
            # Ελεγξε αν το cipher είναι τουλάχιστον μήκους byteIndex
            if (byteIndex < cipherLengths[cipherIndex]):

                # Κάνε την αποκρυπτογράφηση του byte byteIndex του cipher στη θέση 
                Cci = BinaryToNumber(__checkCiphers[cipherIndex][byteIndex])
                Mi_tested = chr(Cci ^ key)

                #Ελεγχος αν ο χαρακτήρας είναι αποδεκτός
                if (Mi_tested not in __ValidDigits):
                    checked = False
                else:
                    Mi_Combinations.append(int(Mi_tested))
            else:
                # Αν το cipher είναι μικρότερου μήκους προσθεσε το κενό ''
                # Δεν υπάρχει κάποιος χαρακτήρας στην αντίστοιχη θέση του plaintext
                Mi_Combinations.append('')

        if (checked == True):
            # Πρόσθεσε το κλειδί που βρήκες στα πιθανά κλειδιά
            possible_keys.append(key)
            # Πρόσθεσε τους συνδυασμούς χαρακτήρων που βρήκαμε στους πιθανούς συνδυασμούς χαρακτήρων
            messages.append(Mi_Combinations)
        Mi_Combinations = []

    # Πρόσθεσε τους πιθανούς συδυασμούς χαρακτήρων στους συνολικούς
    possibleMessageCharacters.append(messages)

    Mis = keytext = ''.join(["M" + str(i + 1) + ', ' for i in range(ciphersCount)])[:-2]

    # Εμφάνισε όλους τους (πιθανούς) συνδυασμούς χαρακτήρων που μπορεί να υπάρχουν στη
    # θέση byteIndex των plaintexts
    print('Possible ' + Mis + ' at byte ' + str(byteIndex) + ' : ', end = '')
    for m in messages:
        print(m, end='')
    print()
    
    # Εμφάνισε όλους τους πιθανούς συνδυασμούς που μπορούν να υπάρχουν στο
    # byte byteIndex των κλειδιών
    print('Possible key at byte ' + str(byteIndex) + ' : ', end = '')
    for key in possible_keys:
        print(NumberToBinary(key), end=' ')
    print()
    print()
    return [possible_keys, possibleMessageCharacters]


# Βρίσκει όλα τα δυνατές τιμές στα αντιστοιχα bytes του κλειδιού που
# που μπορούν να δημιουργήσουν συνδιάζοντας τα το πλήρες κλειδί.
# Επιστρέφεται πίνακας που για κάθε byte του κλειδιού έχει υποπίνακα
# με τις δυνατές τιμές που μπορεί να έχει το συγκεκριμένο byte.
def FindAllKeysAndMessageCharacters(ValidDigits, KeysLeftNibble, checkCiphers):
    global __ValidDigits
    global __KeysLeftNibble
    global __checkCiphers

    __ValidDigits = ValidDigits
    __KeysLeftNibble = KeysLeftNibble
    __checkCiphers = checkCiphers

    messageCharacters = []
    key_combinations = []
    ciphersCount = len(__checkCiphers)

    ciphersLength = [len(c) for c in __checkCiphers]

    for byteIndex in range(max(ciphersLength)):
        checkSet = []

        for checkIndex in range(ciphersCount):
            if (ciphersLength[checkIndex] >= byteIndex):
                checkSet.append(__checkCiphers[checkIndex])
            else:
                # Πρόσθεσέ το ούτως ή άλλως
                checkSet.append(__checkCiphers[checkIndex])

        keysFound, messagesFound = FindAllKeysAndMessageCharactersAtIndex(byteIndex)
        key_combinations.append(keysFound)
        messageCharacters.append(messagesFound)

    return [key_combinations, messageCharacters]


# Συνδιάζει τις τιμές που μπορεί να έχει το κάθε byte του κλειδιού
# ώστε να δώσει όλα το δυνατά κλειδιά.
# Χρησιμοποιείται από την CombineKeys, αλλά και καλείται από το εαυτό της αναδρομικά
# προκειμένου να δημιουργήσει το πλήρες κλειδί.
def CombineSubKeys(countsets, setNo, keystring):
    global __results_count
    global __keys

    # Σε περίπτωση που έχουμε εμφανίσει όλους τους συνδυασμούς κλειδιών και μηνυμάτων
    # που θέλουμε να εμφανίσουμε μην συνεχίσει η επεξεργασία
    # έχουμε δείξει όσα έχει ζητήσει ο χρήστης
    if (__results_count == 0):
        return

    # Ελεγξε αν το τρέχον set κλειδιών είναι μικρότερο από το πλήθος των
    # συνολικών set κλειδιών που έχουμε
    if (setNo < countsets):
        # Για κάθε κλειδί στο set κλειδιών πάρε το και συνδυασέ το με τα κλειδιά των 
        # υπόλοιπων set κλειδιών
        for i in range(len(__keys[setNo])):
            subkey = keystring + " " + NumberToBinary(__keys[setNo][i])
            CombineSubKeys(countsets, setNo+1, subkey)
    else:
        # Τώρα που έχουν γίνει συνδυασμοί κλειδιών από όλα τα set κλειδιών
        # εμφάνισε το κλειδί
        print("Possible key       = " + keystring.strip())

        # Με το κλειδί που έχει βρεθεί θα γίνει η αποκρυπτογράφηση όλων των ciphers
        # και θα εμφανιστούν τα αντίστοιχα plaintexts που παράγονται από την αποκρυπτογράφηση
        global __CiphersToCheck
        ciphersCount = len(__CiphersToCheck)
        ciphersLength = [len(c) for c in __CiphersToCheck]

        # Μετατροπή του συνολικού κλειδιού που έχουμε από binary string σε αριθμούς
        # προκειμένου να γίνει η αποκρυπτογράφηση των ciphertexts
        binaryKey = keystring.replace(' ' ,'')
        binaryKeyList = SplitStringByLength(binaryKey.strip(), 8)
        keyList = [BinaryToNumber(xi) for xi in binaryKeyList]

        # Για κάθε cipher που υπάρχει στη λίστα με τους ciphers κάνουμε την αποκρυπτογράφηση
        # το cipherIndex δείχνει για ποιον cipher πρόκειται (είναι zero based)
        for cipherIndex in range(ciphersCount):
            message = ''
            # Κάνουμε την αποκρυπτογράφηση του κάθε cipher ένα ένα byte κάθε φορά
            # και το αποτέλεσμα το προσθέτουμε στο μήνυμα
            for byteIndex in range(ciphersLength[cipherIndex]):
                # Κάνουμε την αποκρυπτογράφηση του byte στη θέση byteIndex 
                # του cipher στη θέση cipherIndex του πίνακα __CiphersToCheck
                ci = BinaryToNumber(__CiphersToCheck[cipherIndex][byteIndex])
                ki = keyList[byteIndex]
                ch = chr(ci ^ ki)
                # προσθέτουμε τον αποκρυπτογραφημένο χαρακτήρα στο μήνυμα
                message += ch

            # Εμφανίζουμε το μήνυμα που αποκρυπτογραφήθηκε με το κλειδί από τον cipher
            # Χρησιμοποιούμε cipherIndex + 1 επειδή το cipher είναι 0 based, ενώ εμείς
            # θέλουμε να κάνουμε αντιστοίχηση σε 1 based
            print("Possible M" + str(cipherIndex + 1) + " for C" + str(cipherIndex+1) + " = " + message)

        # Μειώνουμε κατά 1 το πλήθος των συνδυασμών που απομένουν να εμφανίσουμε
        # προκειμένου να περιορίσουμε το πλήθος των αποτελεσμάτων που εμφανίζονται
        __results_count = __results_count - 1
        print()


# Συνδιάζει τις τιμές που μπορεί να έχει το κάθε byte του κλειδιού
# ώστε να δώσει όλα το δυνατά κλειδιά.
# Χρησιμοποιεί την CombineKeys
# καλείται από την PrintKeyCombinations
def CombineKeys(keys):
    global __keys

    __keys = keys
    countsets = len(__keys)

    keystring = ""
    currentset = 0

    # Δημιουργία του συνδυασμού κλειδιών από το set κλειδιών που αντιστοιχεί στο byte currentset
    for i in range(len(keys[currentset])):
        subkey = NumberToBinary(keys[currentset][i])
        CombineSubKeys(countsets, currentset+1, subkey)


# Combine keys from keys array and print each combination
def PrintKeyCombinations(keys, CiphersToCheck):
    global __CiphersToCheck

    __CiphersToCheck = CiphersToCheck

    # Ορισε πόσα θα είναι τα είναι τα αποτελέσματα που θα φέρει
    SetMaximumResultsFromUser(keys)
    CombineKeys(keys)


# Ορίζει μέχρι πόσους συνδυασμούς κλειδιών και μηνυμάτων θα εμφανίσει
def SetMaximumResultsFromUser(keys):
    global __results_count
    combinationsNo = CalculateKeyCombinations(keys)
    
    # Προεπιλογή πλήθους αποτελεσμάτων συνδυασμών κλειδιών, μηνυμάτων
    if (len(sys.argv) > 1):
        __results_count = abs(int(sys.argv[1]))
    else:
        # για να μην το περιορίσουμε θα πρέπει να δώσουμε sys.maxsize + 1
        __results_count = 2 # sys.maxsize + 1

    # Εάν έχουμε μέχρι 16 συνδυασμούς τότε να εμφανιστούν όλα
    if (combinationsNo <= 16):
        __results_count = combinationsNo

    if __results_count > combinationsNo:
        __results_count = combinationsNo

    print("Will show up to " + str(__results_count) + "/" + str(combinationsNo) + " possible key and messages combinations.")
    print()

    return __results_count


# Υπολογίζει τους δυνατούς συνδιασμούς κλειδιών, άρα και μηνυμάτων
def CalculateKeyCombinations(keys):
    mc = 1
    for i in range(len(keys)):
        mc = mc * len(keys[i])
    return mc
