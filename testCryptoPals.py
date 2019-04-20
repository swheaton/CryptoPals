__author__ = 'stuart'

import unittest
import CryptoStu

class TestSet1(unittest.TestCase):

    def setUp(self):
        print "Test", self._testMethodName, "::"

    def test_challenge1(self):
        hexVal = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        b64Val = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        self.assertEqual(CryptoStu.hexToB64(hexVal), b64Val)
        self.assertEqual(CryptoStu.b64ToHex(b64Val), hexVal)
        
    def test_challenge2(self):

        #Hex XOR testing
        # same length test
        startStr = "1c0111001f010100061a024b53535009181c"
        xorStr = "686974207468652062756c6c277320657965"
        endStr = "746865206b696420646f6e277420706c6179"
        self.assertEqual(CryptoStu.hexxor(startStr, xorStr), endStr)
        
        # different lengths - we only xor with the shortest of the two
        self.assertEqual(CryptoStu.hexxor("1c0111001f010100061a024b53535009181c", "6869"), "7468")
        self.assertEqual(CryptoStu.hexxor("6869", "1c0111001f010100061a024b53535009181c"), "7468")
        
        #TODO String XOR testing
        
    def test_challenge3(self):

        scoreText = CryptoStu.singleXorDecrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        self.assertEqual(scoreText.text, "Cooking MC's like a pound of bacon")
        self.assertEqual(scoreText.decodeByte, "X")
    
    @unittest.skip("this test takes too long")
    def test_challenge4(self):

        mostLikelyEncryptedString = CryptoStu.findSingleXorCipherInFile("files/p4.txt")
        self.assertEqual(mostLikelyEncryptedString.decodeByte, '5')
        self.assertEqual(mostLikelyEncryptedString.text, "Now that the party is jumping\n")
        
    def test_challenge5(self):
        asciiText ="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        encryptedText = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        self.assertEqual(CryptoStu.repeatingKeyXor(asciiText, "ICE").encode('hex'), encryptedText) #Encrypt
        self.assertEqual(CryptoStu.repeatingKeyXor(encryptedText.decode('hex'), "ICE"), asciiText) #Decrypt

    def test_challenge6(self):

        self.assertEqual(CryptoStu.hammingDist("this is a test", "wokka wokka!!!"), 37)
        self.assertEqual(CryptoStu.guessKeySizeFile("files/p6.txt"), 29)
        solved = CryptoStu.solveVigenereFile("files/p6.txt")
        self.assertEqual(solved[0], "Terminator X: Bring the noise")
        #Just searches for a particular lyric to make sure we at least decrypted some of it
        self.assertNotEqual(solved[1].find("Play that funky music white boy"), -1)
        self.assertNotEqual(solved[1].find("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino"), -1)
        #print solved[1] #Uncomment to print the whole decrypted text
        
    def test_challenge7(self):

        decryptedFile = CryptoStu.decryptAES_ECB_File("files/p7.txt", "YELLOW SUBMARINE")
        self.assertNotEqual(decryptedFile.find("Play that funky music white boy"), -1)
        self.assertNotEqual(decryptedFile.find("I'm back and I'm ringin' the bell"), -1)
        #print decryptedFile #Uncomment to print the whole decrypted text

    def test_challenge8(self):

        blah = 1
        ecbEncryptedCiphers = CryptoStu.findEcbEncryptedCipherFile("files/p8.txt")
        self.assertEqual(len(ecbEncryptedCiphers), 1)
        #print ecbEncryptedCiphers #Uncomment to print the ciphers in the file that are encrypted with ecb

class TestSet2(unittest.TestCase):

    def setUp(self):
        print "Test", self._testMethodName, "::"
    
    def test_challenge9(self):
        #Border case
        padded = CryptoStu.padPKCS7("1234", 4)
        self.assertEqual(padded, "1234\x04\x04\x04\x04")
        #Case in the challenge
        padded = CryptoStu.padPKCS7("YELLOW SUBMARINE", 20)
        self.assertEqual(padded, "YELLOW SUBMARINE\x04\x04\x04\x04")
        #Message longer than block size
        padded = CryptoStu.padPKCS7("12345678", 5)
        self.assertEqual(padded, "12345678\x02\x02")
        
    def test_challenge10(self):
        #The encrypted file from the challenge
        decrypted = CryptoStu.fileAES_CBC("files/p10.txt", "\x00" * 16, "YELLOW SUBMARINE", "dec")
        self.assertNotEqual(decrypted.find("Play that funky music white boy"), -1)
        self.assertNotEqual(decrypted.find("Vanilla's on the mike, man I'm not lazy."), -1)
        #print decrypted #Uncomment to print decrypted file
        
        #Test something that is exactly 16 bytes
        text = "1234567812345678"
        iv = "8765432187654321"
        key = "YELLOW SUBMARINE"
        self.assertEqual(CryptoStu.decryptAES_CBC(CryptoStu.encryptAES_CBC(text, iv, key), iv, key), text)
        self.assertEqual(len(CryptoStu.encryptAES_CBC(text, iv, key)), 32)
        
        #Test something less than 16 bytes (15)
        text = "123456781234567"
        iv = "8765432187654321"
        key = "YELLOW SUBMARINE"
        self.assertEqual(len(CryptoStu.encryptAES_CBC(text, iv, key)), 16)
        self.assertEqual(CryptoStu.decryptAES_CBC(CryptoStu.encryptAES_CBC(text, iv, key), iv, key), text)
        
        #Test something more than 16 bytes (17)
        text = "12345678123456789"
        iv = "8765432187654321"
        key = "YELLOW SUBMARINE"
        self.assertEqual(len(CryptoStu.encryptAES_CBC(text, iv, key)), 32)
        self.assertEqual(CryptoStu.decryptAES_CBC(CryptoStu.encryptAES_CBC(text, iv, key), iv, key), text)
        
    def test_challenge11(self):

        #Try it 100 times, make sure it works
        for i in xrange(0, 100):
            oracleResult = CryptoStu.determineAESMode(CryptoStu.randomEcbCbcOracle, 16)
            self.assertEqual(oracleResult[0], oracleResult[1])
    
    def test_challenge12(self):
        self.assertEqual(CryptoStu.discoverBlockSize_NoPrefix(CryptoStu.fixedKeyEcbOracle), 16)
        self.assertEqual(CryptoStu.determineAESMode(CryptoStu.fixedKeyEcbOracle)[1], 'ecb')
        self.assertNotEqual(CryptoStu.byteEcbDecryptionNoPrefix().find("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by"), -1)
    
    def test_challenge13(self):
        keyValueStr = "foo=bar&baz=qux&zap=zazzle"
        self.assertEqual(CryptoStu.encodeKeyValueObj(CryptoStu.decodeKeyValueObj(keyValueStr)), keyValueStr)
        #Make sure our hack worked! And that our role is admin
        self.assertTrue(["role", "admin"] in CryptoStu.decryptAndParse(CryptoStu.hackAdminAccount()))
        
    def test_challenge14(self):
        #First, let's test out my GCD functions
        self.assertEqual(CryptoStu.gcdTwo(0, 0), 0)
        self.assertEqual(CryptoStu.gcdTwo(32, 24), 8)
        self.assertEqual(CryptoStu.gcdTwo(24, 32), 8)
        self.assertEqual(CryptoStu.gcdTwo(7, 5), 1)
        self.assertEqual(CryptoStu.gcdMult([64, 32, 16]), 16)
        self.assertEqual(CryptoStu.gcdMult([144, 32, 160]), 16)

        #Now, make sure we always think the block size is 16
        for i in xrange(32):
            self.assertEqual(CryptoStu.discoverBlockSize_Prefix(CryptoStu.randomPrefixEcbOracle), 16)
            
    def test_challenge15(self):
        self.assertEqual(CryptoStu.checkAndStripPadding("ICE ICE BABY\x04\x04\x04\x04"), "ICE ICE BABY")
        self.assertRaises(AssertionError, CryptoStu.checkAndStripPadding, "ICE ICE BABY\x05\x05\x05\x05")
        self.assertRaises(AssertionError, CryptoStu.checkAndStripPadding, "ICE ICE BABY\x01\x02\x03\x04")
        
    def test_challenge16(self):
        self.assertTrue(CryptoStu.decryptAndConfirmAdmin(CryptoStu.cbcBitFlip()))
        

class TestSet3(unittest.TestCase):

    def setUp(self):
        print "Test", self._testMethodName, "::"

    def test_challenge17(self):
        self.assertEqual(CryptoStu.cbcPaddingOracleAttack(1).decode('base64'),
            "000001With the bass kicked in and the Vega's are pumpin'")
            
    def test_challenge18(self):
        self.assertEqual(CryptoStu.AES_CTR("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".decode('base64'), "YELLOW SUBMARINE", 0),
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
        text = "Hello, this is a test of a decent-sized stream. We will test encryption and decryption using AES CTR mode!"
        key = "YELLOW SUBMARINE"
        nonce = 123456789
        self.assertEqual(CryptoStu.AES_CTR(CryptoStu.AES_CTR(text, key, nonce), key, nonce), text)
    
    def test_challenge20(self):
        decryptedLines = CryptoStu.crackCTR(CryptoStu.createAesCtrEncryptions("files/p20.txt"))
        self.assertTrue("Ya tremble like a alcoholic, muscles tighten up / Wha" in decryptedLines)
        self.assertTrue("Turn down the bass down / And let the beat just keep " in decryptedLines)
        #print '\n'
        #for line in decryptedLines:
        #    print line
        #Uncomment above to print decrypted lines from the file
        
    #Not sure how to test the MT besides making sure that given the same seed, it gives us the same outputs
    def test_challenge21(self):
        mt = CryptoStu.MT()
        mt.initMT(1234567)
        pseudoRandomNums = [mt.extractNumber() for i in xrange(25)]
        mt.initMT(1234567)
        pseudoRandomNums2 = [mt.extractNumber() for i in xrange(25)]
        self.assertEqual(pseudoRandomNums, pseudoRandomNums2)
    
    @unittest.skip("Takes too long by design")
    def test_challenge22(self):
        createdMT = CryptoStu.createTheOtherMT()
        actualSeed = createdMT[0]
        firstNumber = createdMT[1]
        guessedSeed = CryptoStu.crackMT(firstNumber)
        self.assertEqual(guessedSeed, actualSeed)
        
    def test_challenge23(self):
        #Test untemper function
        mt = CryptoStu.MT()
        value = 9639572
        self.assertEqual(CryptoStu.untemper(mt.temper(value)), value)
        value = 2576459
        self.assertEqual(CryptoStu.untemper(mt.temper(value)), value)
        
        #Initialize the MT with a seed, then see what the first two sets of extracted numbers are
        seed = 74859264
        mt.initMT(seed)
        firstValues = [mt.extractNumber() for i in xrange(624)]
        nextValues = [mt.extractNumber() for i in xrange(624)]
        
        #Initialize it again so we can let the cloneMT function try to predict
        mt.initMT(seed)
        predictedValues = CryptoStu.cloneMT(mt)
        self.assertEqual(predictedValues, nextValues)
        
    @unittest.skip("Too slow due to self-imposed sleep")
    def test_challenge24(self):
        #Test mt stream cipher first
        text = "Hello, this is a test of a decent-sized stream. We will test encryption and decryption using MT PRNG stream mode!"
        seed = 8675309
        self.assertEqual(CryptoStu.mtStreamCipher(CryptoStu.mtStreamCipher(text, seed),seed), text)
        
        mtEncrypted = CryptoStu.encryptMTKnownText()
        originalSeed = mtEncrypted[0]
        encryptedText = mtEncrypted[1]
        guessedSeed = CryptoStu.breakMTKnownText(encryptedText)
        self.assertEqual(guessedSeed, originalSeed)
        
        passwordReset = CryptoStu.genPasswordResetToken()
        originalSeed = passwordReset[0]
        token = passwordReset[1]
        self.assertEqual(CryptoStu.determineMTCurrTime(token, 100), originalSeed)

import hashlib
class TestSet4(unittest.TestCase):
    def setUp(self):
        print "Test", self._testMethodName, "::"

    def test_challenge25(self):
        secretText = "Hello, this is a test of a decent-sized stream. We will test cracking CTR mode of AES if we are allowed to edit!"
        ciphertext = CryptoStu.generateCtrCipherText(secretText)
        plaintext = CryptoStu.crackCtrEdit(ciphertext)
        self.assertEqual(plaintext, secretText)

    def test_challenge26(self):
        self.assertTrue(CryptoStu.decryptAndConfirmAdmin_ctr(CryptoStu.ctrBitFlip()))

    def test_challenge27(self):
        ciphertext = CryptoStu.encryptUserData("A"*5, True)
        guessedKey = CryptoStu.crackSameKeyIvCBC(ciphertext)

        self.assertEqual(guessedKey, CryptoStu.fixedKey)
        
    def test_challenge28_MDPad(self):
        #Test padding function first
        #Test from the RFC
        message = "6162636465".decode('hex')
        paddedMessage = CryptoStu.MDPad(message)
        self.assertEqual(paddedMessage.encode('hex'), "61626364658000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028"
)
        #9 bytes left, we can still use up this block, albeit with no 0's
        message = "1234567812345678123456781234567812345678123456781234567"
        paddedMessage = CryptoStu.MDPad(message)
        self.assertEqual(len(paddedMessage), 64)
        self.assertEqual(int(paddedMessage[-8:].encode('hex'), 16), 55 * 8)

        #Only 8 bytes left, have to use the next block
        message = "12345678123456781234567812345678123456781234567812345678"
        paddedMessage = CryptoStu.MDPad(message)
        self.assertEqual(len(paddedMessage), 128)
        self.assertEqual(int(paddedMessage[-8:].encode('hex'), 16), 56 * 8)
        
        #0 bytes left, make sure we do end up using the next block
        message = "1234567812345678123456781234567812345678123456781234567812345678"
        paddedMessage = CryptoStu.MDPad(message)
        self.assertEqual(len(paddedMessage), 128)
        self.assertEqual(int(paddedMessage[-8:].encode('hex'), 16), 64 * 8)

    def test_challenge28_sha1(self):
        #Test rotateLeft function first
        self.assertEqual(CryptoStu.rotateLeft(0xabcd0000, 16), 0x0000abcd)
        
        #Test my hash against Python's hashlib
        self.assertEqual(CryptoStu.sha1Hash(""), hashlib.sha1("").digest())
        self.assertEqual(CryptoStu.sha1Hash("hello"), hashlib.sha1("hello").digest())
        self.assertEqual(CryptoStu.sha1Hash("trying to get it to fail!"), hashlib.sha1("trying to get it to fail!").digest())

        #No need to test the hmac function, it just is what it is
        
    def test_challenge29(self):
        self.assertTrue(CryptoStu.sha1LengthExtensionAttack())


    def test_challenge30(self):
        #This is a test suite from the MD4 RFC
        self.assertEqual(CryptoStu.md4Hash("").encode('hex'), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(CryptoStu.md4Hash("a").encode('hex'), "bde52cb31de33e46245e05fbdbd6fb24")
        self.assertEqual(CryptoStu.md4Hash("abc").encode('hex'), "a448017aaf21d8525fc10ae87aa6729d")
        self.assertEqual(CryptoStu.md4Hash("message digest").encode('hex'), "d9130a8164549fe818874806e1c7014b")
        self.assertEqual(CryptoStu.md4Hash("abcdefghijklmnopqrstuvwxyz").encode('hex'), "d79e1c308aa5bbcdeea8ed63df412da9")
        self.assertEqual(CryptoStu.md4Hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").encode('hex'), "043f8582f241db351ce627e153e7f0e4")
        self.assertEqual(CryptoStu.md4Hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890").encode('hex'), "e33b4ddc9c38f2199c3e7b164fcc0536")

        #Now test md4 length extension attack
        self.assertTrue(CryptoStu.md4LengthExtensionAttack())

    @unittest.skip("Takes way too long, by design. 40 minutes or so")
    #Uses wall time, so it might not work every time since a brief slow down due
    #   to other processes on the machine can unfairly weight a particular byte
    def test_challenge31(self):
        self.assertTrue(CryptoStu.discoverHashByTimingLeak("attack, attack!"))

    @unittest.skip("Takes way too long, by design. 40 minutes or so")
    def test_challenge32(self):
        self.assertTrue(CryptoStu.discoverHashByTimingLeakAvg("attack, attack!"))
        
class TestSet5(unittest.TestCase):
    def setUp(self):
        print "Test", self._testMethodName, "::"

    def test_challenge33(self):
        self.assertTrue(CryptoStu.diffieHellmanKey())

    def test_challenge34_dhencryption(self):
        message = "Hello!, This is a super secret message only for your eyes and DEFINITELY not a MITM attacker's!"

        networkMgr = CryptoStu.NetworkManager()
        networkMgr.negotiateKeys()

        encrypted = networkMgr.aliceEncrypt(message)
        newMessage = networkMgr.bobDecrypt(encrypted)
        self.assertEqual(message, newMessage)
        encrypted2 = networkMgr.bobEncrypt(newMessage)
        newMessage2 = networkMgr.aliceDecrypt(encrypted2)
        self.assertEqual(newMessage2, message)

    def test_challenge34_mitm(self):
        networkMgr = CryptoStu.ManInTheMiddleNetworkManager()
        networkMgr.negotiateKeys()

        message = "Hello!, This is a super secret message only for your eyes and DEFINITELY not a MITM attacker's!"

        encrypted = networkMgr.aliceEncrypt(message)
        newMessage = networkMgr.bobDecrypt(encrypted)
        self.assertEqual(message, newMessage)
        #Now make sure MITM stole the message too.
        self.assertEqual(networkMgr.getStolenMessage(), message)
        encrypted2 = networkMgr.bobEncrypt(newMessage)
        newMessage2 = networkMgr.aliceDecrypt(encrypted2)
        self.assertEqual(newMessage2, message)
        self.assertEqual(networkMgr.getStolenMessage(), newMessage2)

    def test_challenge35_encryption(self):
        message = "Hello!, This is a super secret message only for your eyes and DEFINITELY not a MITM attacker's!"

        networkMgr = CryptoStu.MitmGParameter()

#didnt decrypt work with p-1
# 35e2b3e303833f218b6f612f5ac73f2b316e3696cf75c3a7bc18ea9050394c7e1ffbb091e5bf35361ff5b17f71ea21250ce3b0c92dfddfe0ecdea87f2aa36d7710894feaede646559b372189d1edc8628a660d51d354c585fb4803b12590da0a3c61f111ac43353855b23778d144c764
        modes = ["1", "p", "p-1"]

        # g = p
        for mode in modes:
            print mode
            networkMgr.negotiateKeys(mode)

            encrypted = networkMgr.aliceEncrypt(message)
            newMessage = networkMgr.bobDecrypt(encrypted)
            self.assertEqual(message, newMessage)
            #Now make sure MITM stole the message too.
            self.assertEqual(networkMgr.getStolenMessage(), message)
            encrypted2 = networkMgr.bobEncrypt(newMessage)
            newMessage2 = networkMgr.aliceDecrypt(encrypted2)
            self.assertEqual(newMessage2, message)
            self.assertEqual(networkMgr.getStolenMessage(), newMessage2)


if __name__ == '__main__':
    unittest.main()
