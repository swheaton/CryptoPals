__author__ = 'stuart'


#set 1:1
def hexToB64(hexVal):
    return hexVal.decode('hex').encode('base64').rstrip()

def b64ToHex(b64):
    return b64.decode('base64').encode('hex').rstrip()


#set 1:2
''' xor two hex strings (chops longer string down to size of shorter)'''
def hexxor(a, b):
    if len(a) > len(b):
        out =  "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a[:len(b)], b)])
    else:
        out =  "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a, b[:len(a)])])
    return out

'''  xor two regular strings (chops longer string down to size of shorter)'''
def xor(a,b):
    if len(a) > len(b):
        out = "".join([chr(ord(x) ^ ord(y)) for (x,y) in zip(a[:len(b)],b)])
    else:
        out = "".join([chr(ord(x) ^ ord(y)) for (x,y) in zip(a,b[:len(a)])])
    return out

#set 1:3
import sys
import string
from collections import namedtuple
ScoreText = namedtuple('ScoreText','score text decodeByte decodeHex')

#Character frequency in the English language, from http://en.algoritmy.net/article/40379/Letter-frequency-English
#   This is a more updated link, if I ever care to make this function more accurate: http://norvig.com/mayzner.html"
#   The link also has stats for letter positioning within a word, n-gram frequency, and n-gram positioning as well.
charFreqList = [
                8.167,#A
                1.492,#B
                2.782,#C
                4.253,#D
                12.702,#E
                2.228,#F
                2.015,#G
                6.094,#H
                6.996,#I
                0.153,#J
                0.772,#K
                4.025,#L
                2.406,#M
                6.749,#N
                7.507,#O
                1.929,#P
                0.095,#Q
                5.987,#R
                6.327,#S
                9.056,#T
                2.758,#U
                0.978,#V
                2.360,#W
                0.150,#X
                1.974,#Y
                0.074#Z
                ]
                
#Build english frequency map for each character, all lower case
#TODO include punctuation, and penalize nonprintable characters
engCharFreq = [0 for i in xrange(256)]
for ind, freq in enumerate(charFreqList):
    engCharFreq[ind+ord('a')] = freq
#Also add frequency of spaces, which is approximately one every 5.1 characters, or ~19%
engCharFreq[ord(' ')] = 100.0 / 5.1

#finds variance from typical english text
def varianceFromEnglish(text):
    variance = 0.0
    textCharFreq = [0 for i in xrange(256)]
    
    #TODO make nonprintable characters create huge variances

    # Create frequency map for this piece of text, so we can compare to english
    for char in text:
        textCharFreq[ord(char.lower())] += 100.0 / len(text)

    # Diff frequencies for text with the one for english, and square the difference
    for ind in xrange(len(textCharFreq)):
        variance += (textCharFreq[ind] - engCharFreq[ind]) ** 2

    return variance

#Finds most likely candidate for decrypted single-byte xor
#   useNonPrintable is true if we assume the key will not be a nonprintable characters
def singleXorDecrypt(hexVal, useNonPrintable=True):
    bestScore = ScoreText(score=sys.float_info.max, text = '',decodeByte='', decodeHex='')

    # Try all characters
    for ind in xrange(256):
        if useNonPrintable == False and chr(ind) not in string.printable:
            continue

        #Get byte in hex, perform the hex xor, then evaluate english potential
        byte = '{0:02x}'.format(ind)
        result = hexxor(hexVal, byte * (len(hexVal) / 2))
        score = varianceFromEnglish(result.decode('hex'))

        # Store best score so far
        if(score < bestScore.score):
            bestScore = ScoreText(score, result.decode('hex'), decodeByte=chr(ind), decodeHex=hex(ind))

    return bestScore

#Set 1:4
# Finds the line in a file that is most likely to have been single-xor encrypted
def findSingleXorCipherInFile(fileName):
    with open(fileName) as file:
        bestPair = ScoreText(score=sys.float_info.max, text = '', decodeByte='', decodeHex='')
        for line in file:
            line = line.rstrip()
            resultPair = singleXorDecrypt(line)
            if(resultPair.score < bestPair.score):
                bestPair = resultPair

    return bestPair

#Set 1:5
#takes in a string and a key, and returns repeating-XOR output, aka Vigenere
def repeatingKeyXor(s, key):
    hexText = s.encode('hex')
    hexKey = key.encode('hex')

    #repeat key up to length of text
    hexKey = hexKey * (len(hexText) / len(hexKey)+1)
    hexKey = hexKey[0:len(hexText)]
    out = hexxor(hexText,hexKey)
    return out.decode('hex')

# Call repeatingKeyXor on text from a file
def repeatingKeyXorFile(fileName, key):
    with open(fileName) as file:
        text = "".join(file.readlines())
        out = repeatingKeyXor(text,key)
        return out

#Set 1:6
import numpy as np
#computes hamming distance between two equal-length strings, aka number of bits
#   that are different between the two
def hammingDist(s1,s2):
    assert(len(s1) == len(s2))
    bitValues = (1 << np.arange(8))[:,None] #Just generates [1, 2, 4, 8, ... , 128]
    # Iterates through each byte of both strings, performs bitwise xor with bitValues using numpy,
    #   then counts non_zero of this result so that we get the hamming distance of the two bytes.
    #   Finally, sums all of that together to get the overall hamming distance
    return sum(np.count_nonzero((np.bitwise_xor(byte1, byte2) & bitValues) != 0) for (byte1, byte2) in zip(bytearray(s1), bytearray(s2)))

# Guess key size of Vigenere-encrypted text
#   Warning: assumes text size is sufficiently large (> 41*5 bytes)
def guessKeySize(text):
    lowestHamSum = sys.float_info.max
    keyGuess = 0
    #Arbitrarily cap key size search at 41
    #   Assumes text is sufficiently large (> 41*5 bytes)
    for keysize in xrange(1,41):
        hamDistList = []
        # Take the first four blocks of size keysize, and compare them against each other
        #   using hammingDist(). Sum the results and normalize with the keysize
        a = [0,keysize,keysize*2,keysize*3]
        pairs = [(x, y) for x in a for y in a if x != y]
        for pair in pairs:
            hamDistList.append(hammingDist(text[pair[0]:(pair[0]+keysize)], text[pair[1]:(pair[1]+keysize)]))
        hamSum = sum(hamDistList) / keysize
        
        # All in one line!! But it's gross, so stick with the spread-out one
        #hamSum2 = sum([hammingDist(text[pair[0]:(pair[0]+keysize)], text[pair[1]:(pair[1]+keysize)]) for pair in [(x, y) for x in xrange(0, keysize*4, keysize) for y in xrange(0, keysize*4, keysize) if x != y]]) / keysize
        
        # Normalized edit distance sum that is the lowest is evidence that that's the key size
        if(hamSum < lowestHamSum):
            lowestHamSum = hamSum
            keyGuess = keysize
            
    return keyGuess

#Call guessKeySize() on contents of a file
def guessKeySizeFile(fileName):
    with open(fileName) as file:
        b64Text = "".join(file.readlines())
        hexText = b64ToHex(b64Text)
        return guessKeySize(hexText.decode('hex'))

#solves repeating-key xor vigenere given hex string of cipher text
def solveVigenere(text):
    #First, guess key size
    keysize = guessKeySize(text)

    #Now, for each byte in the key, concatenate all bytes that would be xor'ed with
    #   that key byte together, and solve as a singleXor decryption to find the key byte
    #   Append them all together, and you have the full key
    key = ''
    for startSpot in xrange(keysize):
        subText = "".join([text[ind] for ind in xrange(startSpot,len(text), keysize)])
        bestPair = singleXorDecrypt(subText.encode('hex'), False)
        key += bestPair.decodeByte
    out = repeatingKeyXor(text, key)
    return (key, out)

#Call solveVigenere() on contents of a file
def solveVigenereFile(fileName):
    with open(fileName) as file:
        b64Text = "".join(file.readlines())
        hexText = b64ToHex(b64Text)
        return solveVigenere(hexText.decode('hex'))
        
#Set 1:7
from Crypto.Cipher import AES

#Use AES in ECB mode, assuming no padding
def decryptAES_ECB_NoPadding(message,key):
    obj = AES.new(key)
    decrypted = obj.decrypt(message)
    return decrypted

#Use AES in ECB mode, first checking padding
def decryptAES_ECB(message, key):
    return checkAndStripPadding(decryptAES_ECB_NoPadding(message,key))

#Decrypt file with AES in ECB mode
def decryptAES_ECB_File(fileName, key):
    with open(fileName) as file:
        message = "".join(file.readlines())
        message = message.decode('base64')
        return decryptAES_ECB(message,key)

#Set 1:8
#Decide if a piece of hex text is encrypted using ECB mode
def isEcbEncryptedCipher(hexText):
    #If there is a block that is repeated twice, ECB mode was most likely
    #    used
    blockSet = set()
    for startInd in xrange(0,len(hexText), 16*2):
        if hexText[startInd:(startInd+16*2)] in blockSet:
            return True
        blockSet.add(hexText[startInd:(startInd+16*2)])
    return False

#Find line in file that was most likely encrypted with ECB mode
def findEcbEncryptedCipherFile(fileName):
    encryptedCiphers = []
    with open(fileName) as file:
        idx = 0
        for line in file:
            if isEcbEncryptedCipher(line):
                encryptedCiphers.append(line)
            idx += 1
    return encryptedCiphers

#Set 2:9
#pads message out to have a size that is a multiple of blockSize, using PKCS7
def padPKCS7(message, blockSize):
    assert blockSize < 256
    diff = blockSize - (len(message) % blockSize)
    diffCh = chr(diff)
    return message + diffCh * diff


#Set 2:10
#Encrypt AES in ECB mode, assuming no padding
def encryptAES_ECB_NoPadding(message,key):
    obj = AES.new(key)
    encrypted = obj.encrypt(message)
    return encrypted

#Encrypt AES in ECB mode, adding padding
def encryptAES_ECB(message, key, needsPadding = True):
    encrypted = encryptAES_ECB_NoPadding(padPKCS7(message, 16), key)
    return encrypted

#Encrypt AES in CBC mode, given an initVector and key
def encryptAES_CBC(message, initVector, key):
    cipherText = ''
    prev = initVector
    
    # First, pad the message to a multiple of block size 16
    message = padPKCS7(message, 16)
    #Now, chunk through each block, encrypt them with ECB by xor'ing the block with
    #   the previous one, then concatenate to the final cipher text
    for ind in xrange(0, len(message), 16):
        prev = encryptAES_ECB_NoPadding(xor(message[ind:(ind+16)],prev), key)
        cipherText += prev

    return cipherText

def decryptAES_CBC(message, initVector, key):
    plainText = ''
    prev = initVector
    
    #Rip through each block, decrypting it and then xor'ing with the previous block
    #   to get the message
    for ind in xrange(0, len(message), 16):
        curr = message[ind:(ind+16)]
        plainText += xor(decryptAES_ECB_NoPadding(curr,key),prev)
        prev = curr
    return checkAndStripPadding(plainText)

#Encrypt or decrypt a file with AES CBC mode
def fileAES_CBC(fileName, initVector, key, encDec):
    assert encDec == 'enc' or encDec == 'dec'
    with open(fileName) as file:
        message = "".join(file.readlines()).decode('base64')
        if(encDec == 'enc'):
            return encryptAES_CBC(message,initVector,key)
        else:
            return decryptAES_CBC(message,initVector,key)

#Set 2:11
from os import urandom
from random import randint
from math import ceil
# Function randomly chooses ECB or CBC mode to encrypt a message with, after first
#   appending and prepending 5-10 random bytes to the message, using a random key every time
def randomEcbCbcOracle(message):
       #Generate a random 16-byte key
       randomKey = urandom(16)

       #Append 5-10 bytes before and after the message
       numBefore = randint(5,10)
       numAfter = randint(5,10)
       actual = urandom(numBefore) + message + urandom(numAfter)
       
       #Encrypt using ECB mode vs CBC mode with 50/50 probability
       choice = 'ecb' if randint(0,1) == 0 else 'cbc'
       if choice == 'ecb':
           ciphertext = encryptAES_ECB(actual,randomKey)
       else:
           initVector = urandom(16)
           ciphertext = encryptAES_CBC(actual,initVector,randomKey)
       return (choice, ciphertext)

#Determines whether an encryption function is using ECB or CBC mode of AES
def determineAESMode(encryptionFunc, preferredLen = 0):
    myMessage = 'A' * 48
    oracleResult = encryptionFunc(myMessage)
    ciphertext = oracleResult[1]
    firstGoodBlock = int (ceil(preferredLen / 16.0)) * 16
    if ciphertext[firstGoodBlock:firstGoodBlock+16] == ciphertext[firstGoodBlock+16:firstGoodBlock + 2*16]:
        mode = 'ecb'
    else:
        mode = 'cbc'
    return (oracleResult[0], mode)

#Set 2:12
fixedKey = urandom(16)

# Using a fixed key, append a message to the user's message, then encrypt in ECB mode
def fixedKeyEcbOracle(message):
    postfix = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    newMessage = message + postfix.decode('base64')
    #TODO fix that the return value has to be this crappy pair for testing
    return ('ecb', encryptAES_ECB(newMessage,fixedKey))

# Discover the block size used for a given encryption function, by giving it
#   subsequently longer messages, and seeing when the length changes. Then,
#   the difference between the two is the block size
def discoverBlockSize_NoPrefix(encryptionFunc):
    lastLen = len(encryptionFunc("A")[1])
    for i in xrange(2,65):
        ciphertext = encryptionFunc("A" * i)[1]
        if(len(ciphertext) != lastLen):
            return abs(len(ciphertext) - lastLen)

#Discover the appended message in fixedKeyEcbOracle() one byte at a time, by placing
#   the unknown byte at the end of block after all 'A' characters. Then we can try all
#   256 possible characters, and match what the oracle tells us is the cipher text for those
#   with what we saw for the actual message, to determine the first byte. Subtract an 'A' to
#   shift the message down one spot, so now we can determine the next byte since we know the
#   block will be 14 'A's plus the first byte we already know. Etc.
def byteEcbDecryptionNoPrefix():
    #First find out the block size
    blockSize = discoverBlockSize_NoPrefix(fixedKeyEcbOracle)
    numBlocks = len(fixedKeyEcbOracle("")[1]) / blockSize

    #Now make sure it's ECB mode
    assert determineAESMode(fixedKeyEcbOracle)[1] == 'ecb'

    prevBlock = 'A' * blockSize
    finalDecrypted = ''
    
    #Iterate through each block that we must discover
    for blockNum in xrange(0,numBlocks):
        #Iterate through each byte in the current block, cracking one byte at a time
        currBlock = ''
        for currByte in xrange(1,blockSize+1):
            targetBlock = fixedKeyEcbOracle('A' * (blockSize - currByte))[1][blockSize * blockNum:blockSize * (blockNum+1)]
            for byte in xrange(0,256):
                cipherGuess = fixedKeyEcbOracle(prevBlock[currByte:blockSize] + currBlock + chr(byte))[1][0:blockSize]
                if targetBlock == cipherGuess:
                    currBlock += chr(byte)
                    break
        finalDecrypted += currBlock
        prevBlock = currBlock
    return finalDecrypted

#Set 2:13
'''
Custom key value parser: from foo=bar&baz=qux&zap=zazzle
creates
{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
'''
def decodeKeyValueObj(kvStr):
    pairList = kvStr.split('&')
    list = []
    for pair in pairList:
        tmp = pair.split('=')
        tuple = (tmp[0],tmp[1])
        list.append(tmp)

    return list

def encodeKeyValueObj(list):
    kvStr = ''
    for pair in list:
        kvStr += pair[0] + '=' + pair[1] + '&'
    #Remove final &, because it's not needed
    return kvStr[0:len(kvStr)-1]

def createProfileForUser(email):
    #Eat = and & characters, so that no injection can occur
    email = email.replace('=','').replace('&','')
    list = [('email',email),('uid','10'),('role','user')]
    return encryptAES_ECB(encodeKeyValueObj(list), fixedKey)

def decryptAndParse(stream):
    return decodeKeyValueObj(decryptAES_ECB(stream,fixedKey))

def hackAdminAccount():
    #Discover ciphertext for a block that just has 'admin' then the real padding amount in it
    craftedEmailMiddleAdmin = 'A' * 10 + padPKCS7('admin',16) + '.us'
    firstCiphertext = createProfileForUser(craftedEmailMiddleAdmin)
    adminBlock = firstCiphertext[16:32]
    
    #Now give it a crafted email address length to make sure that '&role=' ends up 
    #   on the edge of the block, so that we can replace the next part with our
    #   admin block
    craftedEmailBlockAligned = 'stu@h4x0r.com'
    secondCiphertext = createProfileForUser(craftedEmailBlockAligned)

    craftedCiphertext = secondCiphertext[0:(16 * 2)] + adminBlock
    return craftedCiphertext


#Set 2:14
#Prepends random number of bytes, then calls fixedKeyEcbOracle
def randomPrefixEcbOracle(message):
    numRandomBytes = randint(0,256)
    randomBytes = urandom(numRandomBytes)
    return ('ecb', fixedKeyEcbOracle(randomBytes + message)[1])

# Discover the block size used for a given encryption function which might have
#   a prefix randomly added to it, by giving it
#   subsequently longer messages, and keeping track of the lengths. Greatest common
#   divisor is very likely the block size

#First, homegrown gcd functions. Python 3.5 has it included, but we don't have that
def gcdTwo(a, b):
    if b == 0:
        return a
    else:
        return gcdTwo(b, a % b)

#Apply gcdTwo to every sequential pair in the list to find the overall gcd
def gcdMult(numberList):
    return reduce(gcdTwo, numberList)

def discoverBlockSize_Prefix(encryptionFunc):
    lenList = []
    #Is 64 enough data points?? Probably
    for i in xrange(64):
        ciphertext = encryptionFunc("A" * i)[1]
        lenList.append(len(ciphertext))

    return gcdMult(lenList)    
'''
def discoverMaxNumBlocks(blockSize):
    maxSize = 0
    for i in xrange(0,blockSize*2):
        size = len(randomPrefixEcbOracle('')[1])
        print size
        if size > maxSize:
            maxSize = size
    return maxSize / blockSize

def findOneOffBlock(text,blockNum = 0,blockSize = 16):
    cipherSet = set()
    while True:
        cipherBlock = randomPrefixEcbOracle(text)[blockNum*blockSize:(blockNum+1)*blockSize]
        if cipherBlock in cipherSet:
            break
        cipherSet.add(cipherBlock)
    cipherSet.clear()
    return cipherBlock

def byteEcbDecryptionRandPrefix():
    blockSize = discoverBlockSize_Prefix(randomPrefixEcbOracle)
    numBlocks = discoverMaxNumBlocks(blockSize)
    print numBlocks

    prevBlock = 'A' * blockSize
    finalDecrypted = ''
    for blockNum in xrange(0,numBlocks):
        currBlock = ''
        for currByte in xrange(1,blockSize+1):
            targetBlock = findOneOffBlock('A'*(blockSize - currByte),blockNum)
            for byte in xrange(0,256):
                cipherGuess = findOneOffBlock(prevBlock[currByte:blockSize] + currBlock + chr(byte))
                if targetBlock == cipherGuess:
                    print 'byte found: ' + chr(byte)
                    currBlock += chr(byte)
                    break
        finalDecrypted += currBlock
        prevBlock = currBlock
        
    return finalDecrypted
'''

#Set 2:15
#Function defined in challenge 15, but used in previous functions retroactively, particularly AES encryption
def checkAndStripPadding(message):
    padByte = message[len(message) - 1]
    padConvert = ord(padByte)

    if padByte != '\x00' and message[len(message) - padConvert:] == padByte * padConvert:
        message = message[0:len(message) - padConvert]
    else:
        raise AssertionError
    return message

#Set 2:16
fixedIv = urandom(16)
#Encrypt user data, with some stuff prepended and appended
def encryptUserData(data):
    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%2-a%20pound%20of%20bacon'

    #quote out ; and = characters
    data = data.replace(';','%3B').replace('=','%3D')
    message = prefix + data + suffix
    return encryptAES_CBC(message,fixedIv,fixedKey)

#Decrypts ciphertext, and returns true if the key value pair admin=true exists
#   in the decrypted data. It is not possible to get this just from encryptUserData,
#   but if we break the crypto we can!
def decryptAndConfirmAdmin(ciphertext):
    decrypted = decryptAES_CBC(ciphertext,fixedIv,fixedKey)
    return decrypted.find(';admin=true;') != -1

#Perform threeway byte-wise Xor of strings
def threewayXor(encryptedString,targetString,replacedString):
    out = ''
    if len(encryptedString) != len(targetString) or len(targetString) != len(replacedString):
        raise AssertionError
    for (c1,c2,c3) in zip(encryptedString,targetString,replacedString):
        out += chr(ord(c1) ^ ord(c2) ^ ord(c3))
    return out

def cbcBitFlip():
    #The prefix is conveniently 32 bytes. So if we send in 16 A's as userData, block 3
    #   will contain AES_ECB_Encrypt('AAAAAAAAAAAAAAAA' ^ block2).
    test = encryptUserData('A' * 16)
    myBlock = test[32:48]
    
    #Flipping a bit in cipher text completely scrambles the block, but produces an identical
    #   bit flip in the next block, due to the xor property of block chaining
    #   So, since we know the next block starts with ';comment2=%2', let's xor our data block
    #   with the target ';admin=true;' and the known text. This is because block 4 will be
    #   xor'ed with the current block. So if 3-way xor it with the known text, that will be
    #   cancelled out, and replaced with our target. This will jumble up the current block
    #   but the next one (block 4) will now decrypt with the target text in it
    myBlock = threewayXor(myBlock[0:12],';admin=true;',';comment2=%2') + myBlock[12:]

    craftedMessage = test[0:32]+myBlock+test[48:]
    return craftedMessage

#Set 3:17
#random strings
stringList=['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

#Select one of the strings at random, then encrypt it
def chooseString(overrideChoice = -1):
    if overrideChoice > 0 and overrideChoice <= 9:
        choice = stringList[overrideChoice]
    else:
        choice = stringList[randint(0,9)]
    return encryptAES_CBC(choice,fixedIv,fixedKey)

#Decrypt ciphertext, returns true if padding is correct
def consumeAndCheckPadding(ciphertext):
    try:
        decryptAES_CBC(ciphertext,fixedIv,fixedKey)
    except AssertionError:
        return False
    return True

def paddingOracleBlock(blockToDecrypt, prevBlock):
    #Intermediate state AFTER being decrypted by AES, but BEFORE being xor'ed with the prev block
    discoveredIntermediate = ''

    #Discover the block byte by byte, by adding position numbers of bytes at the
    #   beginning, starting from 15 down to 0
    for position in xrange(15,-1,-1):
        #Systematically try every possible byte
        for byte in xrange(0,256):
            #First give position number of random bytes.
            #   Then add our target byte
            #   Finally, we want the final bytes to be \x01 first, \x02\x02 next, and so on.
            #   So, xor our discovered intermediate with one less than what we want to see,
            #   so that we'll be able to tell when the padding ends up being correct
            if consumeAndCheckPadding('\x00' * position + chr(byte) + xor(discoveredIntermediate, chr(16-position) * len(discoveredIntermediate)) + blockToDecrypt):
                 myByte = byte
                 break

        #Xor our pseudo-plaintext byte (which happens to be the target padding number)
        #   with the pseudo ciphertext to get the actual intermediate byte
        myByte ^= (16 - position)
        discoveredIntermediate = chr(myByte) + discoveredIntermediate
        
    #Decrypted = Cipher ^ Intermediate
    return xor(discoveredIntermediate, prevBlock)

#Padding oracle attack. See http://robertheaton.com/2013/07/29/padding-oracle-attack/ for good explanation
def cbcPaddingOracleAttack(overrideChoice = -1):
    #Try and decrypt the string chosen by chooseString()
    toDecrypt = chooseString(overrideChoice)
    prevBlock = fixedIv
    decrypted = ''

    #Perform padding oracle on each block of the ciphertext
    for block in xrange(0,len(toDecrypt),16):
        decrypted += paddingOracleBlock(toDecrypt[block:block+16], prevBlock)

        prevBlock = toDecrypt[block:block+16]
    return checkAndStripPadding(decrypted)


#Set 3:18
import struct

#Returns 64 bit little endian nonce || 64 bit little endian block number, encrypted with key
def getStreamBlock(key, nonce, blockNumber):
    ctrKey = struct.pack('Q',nonce) + struct.pack('<Q',blockNumber)
    return encryptAES_ECB_NoPadding(ctrKey,key)

def AES_CTR(message,key,nonce):
    crypted = ''

    #For each block, get the stream cipher block, then xor
    for ind in xrange(0, len(message),16):
        xorBlock = getStreamBlock(key, nonce, ind/16)
        crypted += xor(message[ind:ind+16], xorBlock)
    return crypted


#Set 3:19 - poor substitution cracking of AES .... I don't wanna do this
#TODO

#Set 3:20
#Cracks CTR mode with a fixed nonce, given a list of ciphertext lines.
#   It is essentially like a Vigenere cipher if there is fixed nonce
def crackCTR(encryptedLines):
    #Truncate all lines to a common size - that of the smallest
    smallestLengthLine = min([len(line) for line in encryptedLines])
    truncatedLines = [line[0:smallestLengthLine] for line in encryptedLines]

    #Treat each character as an individual single xor encryption, so concat
    #   that character from all samples and solve. That will give us the current byte of the key stream
    xorStream = ''
    for ind in xrange(smallestLengthLine):
        subText = "".join([line[ind] for line in truncatedLines])
        bestPair = singleXorDecrypt(subText.encode('hex'), True)
        xorStream += bestPair.decodeByte

    return [xor(line, xorStream) for line in truncatedLines]
            
def createAesCtrEncryptions(fileName):
    with open(fileName) as file:
        lines = file.readlines()
        return [AES_CTR(line.decode('base64'), fixedKey, 0) for line in lines]

'''
#Set 3:21 - Mersenne Twister
mtIndex = 0
mtState = [0 for i in xrange(624)]

def initMT(seed):
    global mtIndex
    global mtState
    mtIndex = 0
    mtState[0] = seed
    for i in xrange(1,624):
        mtState[i] = (1812433253 * (mtState[i-1] ^ (mtState[i-1] >> 30)) + i) & 0xffffffff

def temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 2636928640
    y ^= (y << 15) & 4022730753
    y ^= y >> 18
    return y

def extractNumber():
    global mtIndex
    global mtState
    if mtIndex == 0:
        generateNumbers()

    y = mtState[mtIndex]
    y = temper(y)

    mtIndex = (mtIndex + 1) % 624
    return y

def generateNumbers():
    global mtState
    for i in xrange(624):
        y = (mtState[i] & 0x80000000) + (mtState[(i+1) % 624] & 0x7fffffff)
        mtState[i] = mtState[(i+397) % 624] ^ (y >> 1)
        if y % 2 != 0:
            mtState[i] ^= 2567483615

#Set 3:22
import time
def crackMT():
    time.sleep(randint(40,1000))
    initMT(int(time.time()))
    time.sleep(randint(40,1000))
    firstNumber = extractNumber()
    currTime = int(time.time())
    for t in xrange(currTime - 2000,currTime):
        initMT(t)
        guess = extractNumber()
        if guess == firstNumber:
            return t

    return -1

#Set 3:23
def untemperR18(value):
    return value ^ (value >> 18)

def untemperL15(value):
    value ^= (value << 15) & 4022730753
    return value

def untemperL7(value):
    result = 0
    for i in xrange(0,32,7):
        partMask = int((((2**32-1) >> (32-7))) << (i))
        part = value & partMask
        value ^= int((part << 7) & 2636928640)
        result |= part

    return result

def temperPart(y):
    y ^= (y << 7) & 2636928640
    return y

def untemperR11(value):
    mid = value ^ (value >> 11)
    mid = mid >> 11
    return value ^ mid

def untemper(value):
    value = untemperR18(value)
    value = untemperL15(value)
    value = untemperL7(value)
    value = untemperR11(value)
    return value

def cloneMT():
    initMT(randint(0,2**32-1))
    state = [extractNumber() for i in xrange(624)]
    nextNums = [extractNumber() for i in xrange(624)]
    global mtState
    mtState = [untemper(val) for val in state]
    out = [extractNumber() for i in xrange(624)]

    if nextNums == out:
        print "Got it!"
    else:
        print 'Nope...'

#Set 3:24
def mtStreamCipher(message, seed):
    crypted = ''
    initMT(seed)
    for ind in xrange(0,len(message),4):
        newRandom = extractNumber()
        stringValue = pack('>I',newRandom)
        crypted += xor(stringValue, message[ind:ind+4])
    return crypted

def encryptMTKnownText():
    seed = randint(0,2**16-1)
    numRandBytes = randint(0,64)
    print 'initial seed:',seed
    encrypted = mtStreamCipher(urandom(numRandBytes) + 'A'*14, seed)
    return encrypted

def breakMTKnownText():
    encrypted = encryptMTKnownText()
    padding = 'P' * (len(encrypted) - 14)
    for seed in xrange(0,2**16):
        tryEncrypt = mtStreamCipher(padding + 'A'*14, seed)
        if tryEncrypt[len(tryEncrypt)-14:] == encrypted[len(encrypted)-14:]:
            return seed

    return -1

def genPasswordResetToken():
    initMT(int(time.time()))
    return str(extractNumber())

def determineMTCurrTime(token, amtCheckBackwards):
    currTime = int(time.time())
    print currTime
    for t in xrange(currTime, currTime - amtCheckBackwards, -1):
        initMT(t)
        if token == str(extractNumber()):
            return currTime
    return -1

#test test
#Set 4:25

#print determineMTCurrTime(genPasswordResetToken(),5000)
#print genPasswordResetToken()
#print 'found seed:', breakMTKnownText()
#print mtStreamCipher(mtStreamCipher('hello my name is Stuart and I am cool; here today to just say hello.', 8675309),8675309)
#cloneMT()
#print untemper(temper(93572985))
#print crackMT()
#initMT(105100)
#for i in xrange(10):
#    print extractNumber()
#crackCTR('p20.txt')
#print AES_CTR('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='.decode('base64'), 'YELLOW SUBMARINE', 0)
#print cbcPaddingOracleAttack().decode('base64')
#print consumeAndCheckPadding(chooseString())
#cbcBitFlip()
#print stripPadding('ICE ICE BABY\x04\x04\x04\x04')
#print byteEcbDecryptionRandPrefix()
#print decryptParse(makeAdminAccount())
#print byteEcbDecryption()
#for i in xrange(10):
#    print determineMode(ebc_cbc_encryption,0) + ' guess'
#iv = "\x01\xfa\xbc\x82\x71\x9f\x0b\x3e\xe4\x62\x41\xb6\x13\x21\x48\x78"
#print decryptAES_CBC(encryptAES_CBC("YELLOW SUBMARINE",iv,"YELLOW SUBMARINE"),iv,"YELLOW SUBMARINE")
#print decryptAES(encryptAES("YELLOW SUBMARINE","YELLOW SUBMARINE"),"YELLOW SUBMARINE")
#print fileAES_CBC('p10.txt',iv, "YELLOW SUBMARINE",'dec')
#print xor("YELLOW SUBMARINE", "ELLO GUVNA HOWDY")
#print pad("YELLOW SUBMARINE",20)
#findEcbEncryptedCipherFile('p8.txt')
#print decryptAESFile('p7.txt', 'YELLOW SUBMARINE')
#print hammingDist('this is a test', 'wokka wokka!!!')
#solveVigenereFile('p6.txt')
#print repeatingKeyXorFile('p5.txt','ICE').encode('hex')
#print repeatingKeyXor(repeatingKeyXor("Hello World, I'm Stuart",'pass'),'pass')
#out = findSingleXorCipherInFile("p4.txt")
#print str(out.score) + " " + out.text
#out = singleXorDecrypt('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
#print out.text + ' ' + out.decodeByte
## print hexxor('1c0111001f010100061a024b53535009181c','686974207468652062756c6c277320657965')
#print hexToB64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
'''