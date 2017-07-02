__author__ = 'stuart'

import unittest
import CryptoStu

class TestSet1(unittest.TestCase):

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
    def test_challenge17(self):
        self.assertEqual(CryptoStu.cbcPaddingOracleAttack(1).decode('base64'),
            "000001With the bass kicked in and the Vega's are pumpin'")
    
if __name__ == '__main__':
    unittest.main()
