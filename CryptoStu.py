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

#Character frequency in the English language, from http://norvig.com/mayzner.html
#   The link also has stats for letter positioning within a word, n-gram frequency, and n-gram positioning as well.
charFreqList = [
                8.041,#A
                1.485,#B
                3.344,#C
                3.817,#D
                12.492,#E
                2.403,#F
                1.869,#G
                5.053,#H
                7.569,#I
                0.159,#J
                0.541,#K
                4.069,#L
                2.512,#M
                7.234,#N
                7.641,#O
                2.136,#P
                0.120,#Q
                6.269,#R
                6.513,#S
                9.276,#T
                2.730,#U
                1.053,#V
                1.676,#W
                0.235,#X
                1.665,#Y
                0.090,#Z
                ]
                
#Build english frequency map for each character, all lower case
engCharFreq = [0 for i in xrange(256)]
for ind, freq in enumerate(charFreqList):
    engCharFreq[ind+ord('a')] = freq
#Also add frequency of spaces, which is approximately one every 4.79 characters
engCharFreq[ord(' ')] = 100.0 / 4.79

#Guess at frequencies of punctuation using ordering at this site: http://mdickens.me/typing/theory-of-letter-frequency.html
engCharFreq[ord(',')] = 2.003
engCharFreq[ord('.')] = 1.269
engCharFreq[ord('\'')] = 0.388
engCharFreq[ord('"')] = 0.288
engCharFreq[ord('.')] = 0.288
engCharFreq[ord('!')] = 0.188
engCharFreq[ord('-')] = 0.188

#Totally guess at frequency of numbers
for i in xrange(10):
    engCharFreq[i+ord('0')] = 0.088
    
from math import log

#finds "probability" that text is English. Uses sum(log(freq(character))) for each character
def varianceFromEnglish(text):
    variance = 1.0
    textCharFreq = [0 for i in xrange(256)]
    
    # Create frequency map for this piece of text, so we can compare to english
    for char in text:
        #If we've documented the character frequency, use it
        if engCharFreq[ord(char.lower())] > 0.0:
            variance += log(engCharFreq[ord(char.lower())]/100.0)
        #Nonprintables get a VERY small probability
        elif char not in string.printable:
            variance -=1000
        #Printables that we don't have frequencies for, just get a small probability
        else:
            variance += log(0.000001)

    return variance

#Finds most likely candidate for decrypted single-byte xor
#   useNonPrintable is true if we assume the key will not be a nonprintable characters
def singleXorDecrypt(hexVal, useNonPrintable=True):
    bestScore = ScoreText(score=float('-inf'), text = '',decodeByte='', decodeHex='')

    # Try all characters
    for ind in xrange(256):
        if useNonPrintable == False and chr(ind) not in string.printable:
            continue

        #Get byte in hex, perform the hex xor, then evaluate english potential
        byte = '{0:02x}'.format(ind)
        result = hexxor(hexVal, byte * (len(hexVal) / 2))
        score = varianceFromEnglish(result.decode('hex'))

        # Store best score so far
        if(score > bestScore.score):
            #print "hello"
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

    #quote out ;and = characters
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

#Set 3:21 - Mersenne Twister
#Implemented as found on Wikipedia.
class MT:
    def __init__(self):
        self.mtIndex = 0
        self.mtState = [0 for i in xrange(624)]

    def initMT(self, seed):
        self.mtIndex = 0
        self.mtState[0] = seed
        for i in xrange(1,624):
            self.mtState[i] = (1812433253 * (self.mtState[i-1] ^ (self.mtState[i-1] >> 30)) + i) & 0xffffffff
    
    #Leaving temper non-private so that we can use it to test untemper() in later challenge
    def temper(self, y):
        y ^= y >> 11
        y ^= (y << 7) & 2636928640
        y ^= (y << 15) & 4022730753
        y ^= y >> 18
        return y
    
    def extractNumber(self):
        if self.mtIndex == 0:
            self.__generateNumbers()
    
        y = self.mtState[self.mtIndex]
        y = self.temper(y)
    
        self.mtIndex = (self.mtIndex + 1) % 624
        return y
    
    def __generateNumbers(self):
        global mtState
        for i in xrange(624):
            y = (self.mtState[i] & 0x80000000) + (self.mtState[(i+1) % 624] & 0x7fffffff)
            self.mtState[i] = self.mtState[(i+397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.mtState[i] ^= 2567483615


#Set 3:22
import time

def createTheOtherMT():
    mt = MT()
    currTime = int(time.time())
    mt.initMT(currTime)
    time.sleep(randint(10, 20))
    return (currTime, mt.extractNumber())

#Crack an MT, given its first call to extractNumber(), and that it has recently
#   been initialized with a call to time.time()
def crackMT(firstNum):
    currTime = int(time.time())
    myMT = MT()
    for t in xrange(currTime, currTime - 2000, -1):
        myMT.initMT(t)
        guess = myMT.extractNumber()
        if guess == firstNum:
            return t

    return -1


#Set 3:23
#These set of four untemper functions undo a specific line in the temper() process
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

def untemperR11(value):
    mid = value ^ (value >> 11)
    mid = mid >> 11
    return value ^ mid

#Untemper is the counterpart to the temper() function in MT. Should undo it
def untemper(value):
    value = untemperR18(value)
    value = untemperL15(value)
    value = untemperL7(value)
    value = untemperR11(value)
    return value

#Clones 
def cloneMT(mt):
    #Extract out its 624-integer state
    originalState = [mt.extractNumber() for i in xrange(624)]

    mt.mtState = [untemper(val) for val in originalState]
    out = [mt.extractNumber() for i in xrange(624)]

    return out


#Set 3:24
#Uses MT PRNG to make a stream cipher by emitting a pseudo-random keystream
def mtStreamCipher(message, seed):
    #Init the MT
    crypted = ''
    mt = MT()
    mt.initMT(seed)
    
    #Get a series of pseudo-random integers, then make them into a key stream
    for ind in xrange(0, len(message), 4):
        newRandom = mt.extractNumber()
        #Pack the int into a byte string to become the key stream
        stringValue = struct.pack('>I',newRandom)
        crypted += xor(stringValue, message[ind:ind+4])
    return crypted

#Prepends known text (14 A's) with random number of random bytes
def encryptMTKnownText():
    seed = randint(0,2**16-1)
    numRandBytes = randint(0,64)
    encrypted = mtStreamCipher(urandom(numRandBytes) + 'A'*14, seed)
    return (seed, encrypted)

#Break encryptMTKnownText()'s encrypted text
def breakMTKnownText(encrypted):
    #Dunno what the random bytes were, so just make them padding
    padding = 'P' * (len(encrypted) - 14)
    #Try every possible 16-bit seed
    for seed in xrange(0,2**16):
        #Try encrypting using that seed
        tryEncrypt = mtStreamCipher(padding + 'A'*14, seed)
        #Found the right seed if the known text encryption works out to be the same
        if tryEncrypt[len(tryEncrypt)-14:] == encrypted[len(encrypted)-14:]:
            return seed

    return -1

def genPasswordResetToken():
    mt = MT()
    currTime = int(time.time())
    mt.initMT(currTime)
    time.sleep(10)
    return (currTime, str(mt.extractNumber()))

def determineMTCurrTime(token, amtCheckBackwards):
    currTime = int(time.time())
    myMT = MT()
    for t in xrange(currTime, currTime - amtCheckBackwards, -1):
        myMT.initMT(t)
        if token == str(myMT.extractNumber()):
            return t
    return -1

#Set 4:25
#Edits a ciphertext that has used fixedKey as the key for AES CTR mode, by replacing
#   ciphertext at the offset with encrypted version of newText
fixedNonce = 8675309

def generateCtrCipherText(plaintext):
    return AES_CTR(plaintext, fixedKey, fixedNonce)


def editCtrCiphertext(ciphertext, offset, newText):
    newCiphertext = AES_CTR('\x00' * offset + newText, fixedKey, fixedNonce)
    resultCiphertext = ciphertext[0:offset] + newCiphertext[offset:]
    return resultCiphertext
    
#Crack the edit() function by simply passing in the ciphertext you received
#   as the "new text". AES_CTR will blindly xor the ciphertext with the key
#   stream, giving us the plain text
def crackCtrEdit(ciphertext):
    return editCtrCiphertext(ciphertext, 0, ciphertext)
    
#Set 4:26 TODO

#Set 4:27 TODO

#Set 4:28
#Implemented sha1 hash as per RFC at https://tools.ietf.org/html/rfc3174
def MDPad(message, overrideMessageSize = -1, littleEndian=False):
    BLOCK_SIZE = 16 *4 #16-word block = 64 bytes
    messageSize = len(message)
    
    #If we have room for 8-byte length and a 0x08 byte, at least...
    numBytesRemaining = BLOCK_SIZE - (messageSize % BLOCK_SIZE)

    #At least 9 bytes remaining. Good, we can pad using this block
    if numBytesRemaining >= 9:
        #Add 0x80, then 0x00 (repeatedly) until there are 8 bytes left
        message += '\x80' + '\x00' * (numBytesRemaining - 9)
    #We cannot pad using this block only. Must use next one too
    else:
        #Add 0x80, then 0x00 (repeatedly) to fill up this block. Then fill up the
        #   next block with 0x00 until there are 8 bytes left
        message += '\x80' + '\x00' * (numBytesRemaining + 55)

    #Add big-endian 8-byte original message length
    fmt = '>Q' if not littleEndian else '<Q'
    message += struct.pack(fmt, (overrideMessageSize if overrideMessageSize > 0 else messageSize) * 8)
    assert(len(message) % BLOCK_SIZE == 0)

    return message
    
def rotateLeft(word, numShifts):
    return ((word << numShifts) | (word >> (32-numShifts))) & 0xffffffff

from math import trunc

def sha1Hash(message, overrideMessageSize = -1):
    return sha1Hash_intermediate(message, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0])

def sha1Hash_intermediate(message, intermediateHash, overrideMessageSize = -1):
    message = MDPad(message, overrideMessageSize)

    BLOCK_SIZE = 16 * 4 #16-word block = 64 bytes
    W = [0 for i in xrange(80)]
    constant = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

    #Iterate through each 16-word block (64 bytes) M(i)
    for i in xrange(0, len(message), BLOCK_SIZE):
        messageBlock = message[i:i+BLOCK_SIZE]

        #Initialize W[0]-W[15] to be messageBlock[0]-messageBlock[15]
        for t in xrange(16):
            W[t] = struct.unpack('>I', messageBlock[t*4:t*4+4])[0]

        #Initialize W[16]-W[79] to something else
        for t in xrange(16, 80):
            W[t] = rotateLeft(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)
        A = intermediateHash[0]
        B = intermediateHash[1]
        C = intermediateHash[2]
        D = intermediateHash[3]
        E = intermediateHash[4]
        
        for t in xrange(80):
            ft = 0
            
            #Calculate the f(t;B,C,D), which is based on t
            if t < 20:
                ft = (B & C) | ((~B) & D)
            elif t < 40:
                ft = B ^ C ^ D
            elif t < 60:
                ft = (B & C) | (B & D) | (C & D)
            else:
                ft = B ^ C ^ D
                
            #Temp value, then update the letter registers
            temp = ((((rotateLeft(A, 5) + ft) % 2**32 + E) % 2**32 + W[t]) % 2**32 + constant[trunc(t/20)]) % 2**32
            E = D
            D = C
            C = rotateLeft(B, 30)
            B = A
            A = temp
        
        #Now update intermediateHash
        intermediateHash[0] = (intermediateHash[0] + A) % 2**32
        intermediateHash[1] = (intermediateHash[1] + B) % 2**32
        intermediateHash[2] = (intermediateHash[2] + C) % 2**32
        intermediateHash[3] = (intermediateHash[3] + D) % 2**32
        intermediateHash[4] = (intermediateHash[4] + E) % 2**32
        
    #Intermediate hash values are the final at the end. Pack them into a string
    out = "".join([struct.pack('>I', word) for word in intermediateHash])
    return out
    
def hmac(hashFunc, key, message):
    return hashFunc(key + message)
    
#Set 4:29
#Verifies that message hmac's to hashVal when using fixedKey
def verifyHash(hashFunc, message, hashVal):
    return hmac(hashFunc, fixedKey, message) == hashVal

#Returns hash for the message we are allowed to know about
def getKnownHash(hashFunc):
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    return hmac(hashFunc, fixedKey, message)

#Performs length extension attack to forge a message with ;admin=true in it, which has been
#   hmac'ed by fixedKey
def sha1LengthExtensionAttack():
    #Extract out each of the 5 words in the hash
    knownHash = getKnownHash(sha1Hash)
    wordLength = len(knownHash)/5
    intermediateHash = list(struct.unpack('>IIIII', knownHash))

    knownMessage = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    #Now, use length extension to add admin privileges and get the hash
    lengthExtendedHash = sha1Hash_intermediate(";admin=true", intermediateHash, len(MDPad(knownMessage) + ";admin=true"))

    #Guess that the key is size 16
    MDPaddedMessage = MDPad('\x00' * 16 + knownMessage)
    
    #Now concat knownMessage with pseudo-padding, then our attack
    attackMessage = knownMessage + MDPaddedMessage[len(knownMessage)+16:] + ";admin=true"

    #Verify that we've forged the HMAC for attackMessage, which includes admin privileges!
    return verifyHash(sha1Hash, attackMessage, lengthExtendedHash)
    
#Set 4:30
#Implemented MD4 as per RFC at https://tools.ietf.org/html/rfc1320
def md4Hash(message, overrideMessageSize = -1):
    return md4Hash_intermediate(message, [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476])

'''Round 1.
    Let [abcd k s] denote the operation
    a = (a + F(b,c,d) + X[k]) <<< s. 
    F(X,Y,Z) = XY v not(X) Z
'''
def __md4F(x, y, z):
    return (x & y) | (~x & z)
def __md4Round1(a, b, c, d, x, numShifts):
    return rotateLeft((a + __md4F(b, c, d) + x) % 2**32, numShifts)

'''Round 2.
    Let [abcd k s] denote the operation
    a = (a + G(b,c,d) + X[k] + 5A827999) <<< s.
    G(X,Y,Z) = XY v XZ v YZ
'''
def __md4G(x, y, z):
    return (x & y) | (x & z) | (y & z)
def __md4Round2(a, b, c, d, x, numShifts):
    return rotateLeft((a + __md4G(b, c, d) + x + 0x5A827999) % 2**32, numShifts)

'''Round 3.
    Let [abcd k s] denote the operation
    a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s.
    H(X,Y,Z) = X xor Y xor Z
'''
def __md4H(x, y, z):
    return x ^ y ^ z
def __md4Round3(a, b, c, d, x, numShifts):
    return rotateLeft((a + __md4H(b, c, d) + x + 0x6ED9EBA1) % 2**32, numShifts)

#No need for padding function, sha1 uses the same one. We call it MDPad()
def md4Hash_intermediate(message, intermediateHash, overrideMessageSize = -1):
    #Call MDPad, but make the length at the end be little endian
    message = MDPad(message, overrideMessageSize, True)
    BLOCK_SIZE = 16 * 4 #16-word block = 64 bytes
    assert(len(message) % BLOCK_SIZE == 0)

    #Iterate through each 16-word block (64 bytes)
    for i in xrange(0, len(message), BLOCK_SIZE):
        messageBlock = message[i:i+BLOCK_SIZE]

        #Initialize X[0]-X[15] to be messageBlock[0]-messageBlock[15], little-endian
        x = list(struct.unpack("<16I", messageBlock))

        #Copy intermediateHash to be the hash additives
        h = list(intermediateHash)

        shift = [
                [3, 7, 11, 19],
                [3, 5, 9, 13],
                [3, 9, 11, 15]
            ]

        #Round 1
        for k in xrange(16):
            index = (16-k) % 4
            xIndex = k
            h[index] = __md4Round1(h[index], h[(index+1)%4], h[(index+2)%4], h[(index+3)%4], x[xIndex], shift[0][k%4])

        #Round 2
        for k in xrange(16):
            index = (16-k) % 4
            xIndex = 4*(k%4) + k//4
            h[index] = __md4Round2(h[index], h[(index+1)%4], h[(index+2)%4], h[(index+3)%4], x[xIndex], shift[1][k%4])
        
        #Round 3
        seq = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for k in xrange(16):
            index = (16-k) % 4
            xIndex = seq[k]
            h[index] = __md4Round3(h[index], h[(index+1)%4], h[(index+2)%4], h[(index+3)%4], x[xIndex], shift[2][k%4])
        
        for k in xrange(4):
            intermediateHash[k] = (intermediateHash[k] + h[k]) % 2**32

    #Intermediate hash values are the final at the end. Pack them into a string, little-endian
    out = "".join([struct.pack('<I', word) for word in intermediateHash])
    return out
    
    
#Performs length extension attack to forge a message with ;admin=true in it, which has been
#   hmac'ed by fixedKey
def md4LengthExtensionAttack():
    #Extract out each of the 5 words in the hash
    knownHash = getKnownHash(md4Hash)
    wordLength = len(knownHash)/4
    intermediateHash = list(struct.unpack('<IIII', knownHash))

    knownMessage = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    #Now, use length extension to add admin privileges and get the hash
    lengthExtendedHash = md4Hash_intermediate(";admin=true", intermediateHash, len(MDPad(knownMessage) + ";admin=true"))

    #Guess that the key is size 16
    MDPaddedMessage = MDPad('\x00' * 16 + knownMessage, -1, True)
    
    #Now concat knownMessage with pseudo-padding, then our attack
    attackMessage = knownMessage + MDPaddedMessage[len(knownMessage)+16:] + ";admin=true"

    #Verify that we've forged the HMAC for attackMessage, which includes admin privileges!
    return verifyHash(md4Hash, attackMessage, lengthExtendedHash)