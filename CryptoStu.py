__author__ = 'stuart'


#set 1:1
def hexToB64(hexVal):
    return hexVal.decode('hex').encode('base64').rstrip()

def b64ToHex(b64):
    return b64.decode('base64').encode('hex').rstrip()


#set 1:2
def hexxor(a, b):     # xor two hex strings of different lengths
    if len(a) > len(b):
        out =  "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a[:len(b)], b)])
    else:
        out =  "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a, b[:len(a)])])
    return out

def xor(a,b): # xor two regular strings of different lengths
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

#finds variance from typical english of text
def varianceFromEnglish(text):
    variance = 0.0
    textCharFreq = []
    engCharFreq = []
    for i in xrange(256):
        textCharFreq.append(0)
        engCharFreq.append(0)

    for ind, freq in enumerate(charFreqList):
        engCharFreq[ind+ord('a')] = freq
        engCharFreq[ind+ord('A')] = freq
    engCharFreq[ord(' ')] = 100.0 / 5.1
    
    #TODO make nonprintable characters create huge variances

    for char in text:
        textCharFreq[ord(char)] += 100.0 / len(text)

    for ind in xrange(len(textCharFreq)):
        variance += (textCharFreq[ind] - engCharFreq[ind]) ** 2

    return variance

#Finds most likely candidate for decrypted single-byte xor
def singleXorDecrypt(hexVal, useNonPrintable=True):
    bestScore = ScoreText(score=sys.float_info.max, text = '',decodeByte='', decodeHex='')

    for ind in xrange(256):
        if useNonPrintable == False and chr(ind) not in string.printable:
            continue

        byte = hex(ind)
        byte = byte[2:]
        if len(byte) == 1:
            byte = '0' + byte

        result = hexxor(hexVal, byte * (len(hexVal) / 2))
        score = varianceFromEnglish(result.decode('hex'))

        if(score < bestScore.score):
            bestScore = ScoreText(score, result.decode('hex'), decodeByte=chr(ind), decodeHex=hex(ind))

    return bestScore

#Set 1:4
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
def repeatingKeyXor(s, key): #takes in a string and a key, and returns repeating-XOR output
    hexText = s.encode('hex')
    hexKey = key.encode('hex')

    #repeat key up to length of text
    hexKey = hexKey * (len(hexText) / len(hexKey)+1)
    hexKey = hexKey[0:len(hexText)]
    out = hexxor(hexText,hexKey)
    return out.decode('hex')

def repeatingKeyXorFile(fileName, key):
    with open(fileName) as file:
        text = "".join(file.readlines())
        out = repeatingKeyXor(text,key)
        return out

#Set 1:6
import numpy as np
def hammingDist(s1,s2): #computes hamming distance between two equal-length strings
    assert(len(s1) == len(s2))
    bitValues = (1 << np.arange(8))[:,None] #Just generates [1, 2, 4, 8, ... , 128]
    return sum(np.count_nonzero((np.bitwise_xor(byte1, byte2) & bitValues) != 0) for (byte1, byte2) in zip(bytearray(s1), bytearray(s2)))

def guessKeySize(text):
    lowestHamSum = sys.float_info.max
    keyGuess = 0
    for keysize in xrange(1,41):
        hamDistList = []
        a = [0,keysize,keysize*2,keysize*3]
        pairs = [(x, y) for x in a for y in a]
        for pair in pairs:
            if pair[0] == pair[1]:
                continue;
            hamDistList.append(hammingDist(text[pair[0]:(pair[0]+keysize)],text[pair[1]:(pair[1]+keysize)]))
        hamSum = sum(hamDistList) / keysize
        if(hamSum < lowestHamSum):
            lowestHamSum = hamSum
            keyGuess = keysize

        #hamSum = sum([hammingDist(text[startInd:(startInd+keysize)],text[(startInd+keysize):(startInd+keysize*2)])/keysize for startInd in xrange(0,keysize*3,keysize)])
    return keyGuess
    
def guessKeySizeFile(fileName):
    with open(fileName) as file:
        b64Text = "".join(file.readlines())
        hexText = b64ToHex(b64Text)
        return guessKeySize(hexText.decode('hex'))

def solveVigenere(text): #solves repeating-key xor vigenere given hex string of cipher text
    keysize = guessKeySize(text)
    print "\nkey size: ", keysize

    key = ''
    for startSpot in xrange(keysize):
        subText = "".join([text[ind] for ind in xrange(startSpot,len(text), keysize)])
        bestPair = singleXorDecrypt(subText.encode('hex'), False)
        key += bestPair.decodeByte
    print "\nKEY: " + key + '\n==============================\n\n\n\n'
    out = repeatingKeyXor(text, key)
    print out
    return (key, out)

def solveVigenereFile(fileName):
    with open(fileName) as file:
        b64Text = "".join(file.readlines())
        hexText = b64ToHex(b64Text)
        return solveVigenere(hexText.decode('hex'))
        
'''
#Set 1:7
from Crypto.Cipher import AES

def decryptAESNoPadding(message,key):
    obj = AES.new(key)
    decrypted = obj.decrypt(message)
    return decrypted

def decryptAES(message, key):
    return checkAndStripPadding(decryptAESNoPadding(message,key))

def decryptAESFile(fileName, key):
    with open(fileName) as file:
        message = "".join(file.readlines())
        message = message.decode('base64')
        return decryptAES(message,key)

#Set 1:8
def isEcbEncryptedCipher(hexText): #takes in hex text
    blockSet = set()
    for startInd in xrange(0,len(hexText), 16*2):
        if hexText[startInd:(startInd+16*2)] in blockSet:
            return True
        blockSet.add(hexText[startInd:(startInd+16*2)])
    return False

def findEcbEncryptedCipherFile(fileName):
    with open(fileName) as file:
        idx = 0
        for line in file:
            if isEcbEncryptedCipher(line):
                print str(idx) +': ' + line
            idx += 1

#Set 2:9
def pad(message, length): #pads message out to length number of bytes with pkcs #7 method
    diff = length - len(message)
    assert diff >= 0 and diff < 256
    diffCh = chr(diff)
    return message + diffCh * diff

#Set 2:10
def encryptAESNoPadding(message,key): #encrypts block without padding
    obj = AES.new(key)
    encrypted = obj.encrypt(message)
    return encrypted

def encryptAES(message, key, needsPadding = True):
    encrypted = encryptAESNoPadding(pad(message,len(message) + 16 - len(message) % 16),key)

    return encrypted

def encryptAES_CBC(message, initVector, key):
    cipherText = ''
    prev = initVector
    ind = -16
    for ind in xrange(0,len(message)-15, 16):
        prev = encryptAESNoPadding(xor(message[ind:(ind+16)],prev), key)
        cipherText += prev
    ind += 16
    cipherText += encryptAESNoPadding(xor(pad(message[ind:],16),prev), key)

    return cipherText

def decryptAES_CBC(message, initVector, key):
    plainText = ''
    prev = initVector
    ind = -16
    for ind in xrange(0,len(message)-16, 16):
        curr = message[ind:(ind+16)]
        plainText += xor(decryptAESNoPadding(curr,key),prev)
        prev = curr
    ind += 16
    curr = decryptAESNoPadding(message[ind:],key)
    plainText += xor(curr,prev)
    #return plainText
    return checkAndStripPadding(plainText)

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
def ebc_cbc_encryption(message):
       randomKey = urandom(16)
       numBefore = randint(2,5)
       numAfter = randint(2,5)
       actual = urandom(numBefore) + message + urandom(numAfter)
       choice = 'ecb' if randint(0,1) == 0 else 'cbc'
       if choice == 'ecb':
           print 'ecb used'
           ciphertext = encryptAES(actual,randomKey)
       else:
           print 'cbc used'
           initVector = urandom(16)
           ciphertext = encryptAES_CBC(actual,initVector,randomKey)
       return ciphertext

def determineMode(encryptionFunc, prefLen = 0):
    myMessage = 'A' * 48
    ciphertext = encryptionFunc(myMessage)
    firstGoodBlock = int (ceil(prefLen / 16.0)) * 16
    if ciphertext[firstGoodBlock:firstGoodBlock+16] == ciphertext[firstGoodBlock+16:firstGoodBlock + 2*16]:
        mode = 'ecb'
    else:
        mode = 'cbc'
    return mode

#Set 2:12
fixedKey = urandom(16)

def fixedKeyOracle(message):
    prefix = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    newMessage = message + prefix.decode('base64')
    return encryptAES(newMessage,fixedKey)

def discoverBlockSize(encryptionFunc):
    lastLen = len(encryptionFunc("A"))
    for i in xrange(2,65):
        ciphertext = encryptionFunc("A" * i)
        if(len(ciphertext) != lastLen):
            return abs(len(ciphertext) - lastLen)


def byteEcbDecryptionNoPrefix():
    blockSize = discoverBlockSize(fixedKeyOracle)
    print 'block size found:',blockSize
    numBlocks = len(fixedKeyOracle("")) / blockSize
    print 'number of blocks to discover:',numBlocks

    if determineMode(fixedKeyOracle) == 'ecb':
        print 'ecb mode confirmed'
    else:
        raise BaseException

    prevBlock = 'A' * blockSize
    finalDecrypted = ''
    for blockNum in xrange(0,numBlocks):
        currBlock = ''
        for currByte in xrange(1,blockSize+1):
            targetBlock = fixedKeyOracle('A' * (blockSize - currByte))[blockSize * blockNum:blockSize * (blockNum+1)]
            for byte in xrange(0,256):
                cipherGuess = fixedKeyOracle(prevBlock[currByte:blockSize] + currBlock + chr(byte))[0:blockSize]
                if targetBlock == cipherGuess:
                    print 'byte found: ' + chr(byte)
                    currBlock += chr(byte)
                    break
        finalDecrypted += currBlock
        prevBlock = currBlock
    return finalDecrypted


#Set 2:13
def decodeKeyValueObj(kvStr):
    pairList = kvStr.split('&')
    list = []
    for pair in pairList:
        tmp = pair.split('=')
        tuple= (tmp[0],tmp[1])
        list.append(tuple)

    return list

def encodeKeyValueObj(list):
    kvStr = ''
    for pair in list:
        kvStr += pair[0] + '=' + pair[1] + '&'
    return kvStr[0:len(kvStr)-1]

def profile_for(email):
    email = email.replace('=','').replace('&','')
    list = [('email',email),('uid','10'),('role','user')]
    return encryptAES(encodeKeyValueObj(list),fixedKey)

def decryptParse(stream):
    return decodeKeyValueObj(decryptAES(stream,fixedKey))

def makeAdminAccount():
    craftedEmailMiddleAdmin = 'A' * 10 + pad('admin',16) + '.us'
    firstCiphertext = profile_for(craftedEmailMiddleAdmin)
    adminBlock = firstCiphertext[16:32]
    craftedEmailBlockAligned = 'attacker1.com'
    secondCiphertext = profile_for(craftedEmailBlockAligned)

    craftedCiphertext = secondCiphertext[0:(16 * 2)] + adminBlock
    return craftedCiphertext

#Set 2:14
def randomPrefixOracle(message):
    numRandomBytes = randint(0,0)
    randomBytes = urandom(numRandomBytes)
    return fixedKeyOracle(randomBytes + message)

def findOneOffBlock(text,blockNum = 0,blockSize = 16):
    cipherSet = set()
    while True:
        cipherBlock = randomPrefixOracle(text)[blockNum*blockSize:(blockNum+1)*blockSize]
        if cipherBlock in cipherSet:
            break
        cipherSet.add(cipherBlock)
    cipherSet.clear()
    return cipherBlock

def discoverMaxNumBlocks(blockSize):
    maxSize = 0
    for i in xrange(0,blockSize*2):
        size = len(randomPrefixOracle(''))
        if size > maxSize:
            maxSize = size
    return maxSize / blockSize


def byteEcbDecryptionRandPrefix():
    blockSize = discoverBlockSize(randomPrefixOracle)
    numBlocks = discoverMaxNumBlocks(blockSize)

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

    return


#Set 2:15
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
def encryptUserData(data):
    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%2-a%20pound%20of%20bacon'

    #remove ; and =
    data = data.replace(';','%3B').replace('=','%3D')
    message = prefix + data + suffix
    return encryptAES_CBC(message,fixedIv,fixedKey)

def decryptAndConfirmAdmin(ciphertext):
    decrypted = decryptAES_CBC(ciphertext,fixedIv,fixedKey)
    print decrypted
    return decrypted.find(';admin=true;') != -1

def threewayXor(encryptedString,targetString,replacedString):
    out = ''
    if len(encryptedString) != len(targetString) or len(targetString) != len(replacedString):
        raise AssertionError
    for (c1,c2,c3) in zip(encryptedString,targetString,replacedString):
        out += chr(ord(c1) ^ ord(c2) ^ ord(c3))
    return out

def cbcBitFlip():
    test = encryptUserData('A' * 16)
    myBlock = test[32:48]
    myBlock = threewayXor(myBlock[0:12],';admin=true;',';comment2=%2') + myBlock[12:]

    craftedMessage = test[0:32]+myBlock+test[48:]

    if decryptAndConfirmAdmin(craftedMessage):
        print 'yay admin'
    else:
        print 'boo no admin'

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

def chooseString():
    choice = stringList[randint(0,9)]
    return encryptAES_CBC(choice,fixedIv,fixedKey)

def consumeAndCheckPadding(ciphertext):
    try:
        decryptAES_CBC(ciphertext,fixedIv,fixedKey)
    except AssertionError:
        return False
    return True


def xorStringWithRepeatedNumber(discoveredIntermediate, number):
    return "".join([chr(ord(byte) ^ number) for byte in discoveredIntermediate])

def paddingOracleBlock(blockToDecrypt, prevBlock):
    discoveredIntermediate = ''
    decrypted = ''

    for position in xrange(15,-1,-1):
        for byte in xrange(0,256):
            if consumeAndCheckPadding('\x00' * position + chr(byte) + xorStringWithRepeatedNumber(discoveredIntermediate,(16-position)) + blockToDecrypt):
                 myByte = byte
                 break

        myByte ^= (16 - position)
        discoveredIntermediate = chr(myByte) + discoveredIntermediate
        decrypted = chr(ord(prevBlock[position]) ^ myByte) + decrypted

    return decrypted

def cbcPaddingOracleAttack():
    toDecrypt = chooseString()
    prevBlock = fixedIv
    decrypted = ''

    for block in xrange(0,len(toDecrypt),16):
        decrypted += paddingOracleBlock(toDecrypt[block:block+16], prevBlock)

        prevBlock = toDecrypt[block:block+16]
    return checkAndStripPadding(decrypted)

#Set 3:18
from struct import pack

def getStreamBlock(key, nonce, blockNumber):
    ctrKey = pack('Q',nonce) + pack('<Q',blockNumber)
    return encryptAESNoPadding(ctrKey,key)

def AES_CTR(message,key,nonce):
    crypted = ''
    for ind in xrange(0,len(message),16):
        xorBlock = getStreamBlock(key, nonce, ind/16)
        crypted += xor(message[ind:ind+16], xorBlock)
    return crypted

#Set 3:19 - poor substitution cracking of AES .... I don't wanna do this

#Set 3:20
def crackCTR(fileName):
    with open(fileName) as file:
        lines = file.readlines()
        encryptedLines = [AES_CTR(line.decode('base64'),'YELLOW SUBMARINE',0) for line in lines]

        smallestLengthLine = min([len(line) for line in encryptedLines])
        print smallestLengthLine
        truncatedLines = [line[0:smallestLengthLine] for line in encryptedLines]

        xorStream = ''
        for ind in xrange(smallestLengthLine):
            subText = "".join([line[ind] for line in truncatedLines])
            bestPair = singleXorDecrypt(subText.encode('hex'), True)
            xorStream += bestPair.decodeByte

        for line in truncatedLines:
            print xor(line,xorStream)

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