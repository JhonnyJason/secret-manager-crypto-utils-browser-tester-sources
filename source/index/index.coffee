import Modules from "./allmodules"
import domconnect from "./indexdomconnect"
domconnect.initialize()

global.allModules = Modules

############################################################
appStartup = ->
    # document.addEventListener("click", runAllTest)
    runAllTest()
    return

############################################################
run = ->
    promises = (m.initialize() for n,m of Modules when m.initialize?) 
    await Promise.all(promises)
    appStartup()

############################################################
run()



############################################################
runAllTest = ->

    # testBytesToBigInt()
    # testBytesToUtf8()
    # testBytesToHex()
    # testUtf8ToBytes()
    # testHexToBytes()

    await testShas()
    await testPublicKey()
    await testSignatures()
    await testsymmetricEncryption()
    await testAsymmetricEncryption()
    await testSalts() # success

    await testAuthCode()
    await testSessionKey()
    await testCreateSharedSecretHash()
    await testCreateSharedSecretRaw()
    await testReferencedSharedSecretHash()
    await testReferencedSharedSecretRaw()

    evaluate()

evaluate = ->
    console.log(JSON.stringify(results, null, 4))


############################################################
#region secret-manager-crypto-utils tests
import * as secUtl from "./browser"
import * as tbut from "thingy-byte-utils"

results = {}
testString = "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^"
count = 100

############################################################
testShas = ->
    try
        sha256Hex = await secUtl.sha256Hex(testString)
        sha256Bytes = await secUtl.sha256Bytes(testString)    

        sha512Hex = await secUtl.sha512Hex(testString)
        sha512Bytes = await secUtl.sha512Bytes(testString)    

        isMatch256 = sha256Hex == tbut.bytesToHex(sha256Bytes)
        isMatch512 = sha512Hex == tbut.bytesToHex(sha512Bytes)

        if(isMatch256 and isMatch512)
            success = true

            c = count
            before = performance.now()
            while(c--)
                sha512Hex = await secUtl.sha512Hex(testString)

            after = performance.now()
            sha512HexMS = after - before

            c = count
            before = performance.now()
            while(c--)
                sha512Bytes = await secUtl.sha512Bytes(testString)

            after = performance.now()
            sha512BytesMS = after - before


            c = count
            before = performance.now()
            while(c--)
                sha256Hex = await secUtl.sha256Hex(testString)

            after = performance.now()
            sha256HexMS = after - before

            c = count
            before = performance.now()
            while(c--)
                sha256Bytes = await secUtl.sha256Bytes(testString)

            after = performance.now()
            sha256BytesMS = after - before            

            results.testShas = { success, sha256HexMS, sha256BytesMS, sha512HexMS, sha512BytesMS }
        else
            results.testShas="Error! Hex did not match the bytes version."
    catch error
        results.testShas=error.message

############################################################
testPublicKey = ->
    try
        keyPairHex = await secUtl.createKeyPairHex()
        keyPairBytes = await secUtl.createKeyPairBytes()    

        pubHex = await secUtl.createPublicKeyHex(keyPairHex.secretKeyHex)
        pubBytes = await secUtl.createPublicKeyBytes(keyPairBytes.secretKeyBytes)    

        isMatchHex = pubHex == keyPairHex.publicKeyHex
        isMatchBytes = JSON.stringify(pubBytes) == JSON.stringify(keyPairBytes.publicKeyBytes)

        if(isMatchHex and isMatchBytes)
            success = true

            c = count
            before = performance.now()
            while(c--)
                pubHex = await secUtl.createPublicKeyHex(keyPairHex.secretKeyHex)

            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--)
                pubBytes = await secUtl.createPublicKeyBytes(keyPairBytes.secretKeyBytes)

            after = performance.now()
            bytesMS = after - before

            results.testPublicKey = { success, hexMS, bytesMS }
        else
            results.testPublicKey="Error! Created publicKey did not match pregenerated!"
    catch error
        results.testPublicKey=error.message

############################################################
testSignatures = ->
    try
        { secretKeyBytes, publicKeyBytes } = await secUtl.createKeyPairBytes()
        { secretKeyHex, publicKeyHex } = await secUtl.createKeyPairHex()

        signatureBytes = await secUtl.createSignatureBytes(testString, secretKeyBytes)
        verifiedBytes = await secUtl.verifyBytes(signatureBytes, publicKeyBytes, testString)

        signatureHex = await secUtl.createSignatureHex(testString, secretKeyHex)
        verifiedHex = await secUtl.verifyHex(signatureHex, publicKeyHex, testString)

        if(verifiedBytes and verifiedHex)
            success = true

            c = count
            before = performance.now()
            while(c--)
                signatureHex = await secUtl.createSignatureHex(testString, secretKeyHex)
                verifiedHex = await secUtl.verifyHex(signatureHex, publicKeyHex, testString)

            after = performance.now()
            hexMS = after - before


            c = count
            before = performance.now()
            while(c--)
                signatureBytes = await secUtl.createSignatureBytes(testString, secretKeyBytes)
                verifiedBytes = await secUtl.verifyBytes(signatureBytes, publicKeyBytes, testString)

            after = performance.now()
            bytesMS = after - before


            results.testSignatures= {success, hexMS, bytesMS}
        else
            error =  "Error: Signature not verified"
            results.testSignatures = {error, verifiedBytes, verifiedHex}
    catch error
        results.testSignatures=error.message

############################################################
testsymmetricEncryption = ->
    try
        keyHex = await secUtl.createSymKeyHex()

        gibbrishHex = await secUtl.symmetricEncryptHex(testString, keyHex)    
        decrypted = await secUtl.symmetricDecrypt(gibbrishHex, keyHex)

        hexMatched = decrypted == testString

        keyBytes = await secUtl.createSymKeyBytes()
        gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
        decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)
        
        bytesMatched = decrypted == testString
        if(hexMatched and bytesMatched)
            success = true
            c = count
            before = performance.now()
            while(c--)
                gibbrishHex = await secUtl.symmetricEncryptHex(testString, keyHex)
                decrypted = await secUtl.symmetricDecrypt(gibbrishHex, keyHex)

            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--)
                gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
                decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)

            after = performance.now()
            bytesMS = after - before

            results.testsymmetricEncryption = {success, hexMS, bytesMS}
        else
            results.testsymmetricEncryption = "Error: Decrypted did not match original content!"
    catch error
        results.testsymmetricEncryption = error.message

############################################################
testAsymmetricEncryption = ->
    try
        { secretKeyHex, publicKeyHex } = await secUtl.createKeyPairHex()
        { secretKeyBytes, publicKeyBytes } = await secUtl.createKeyPairBytes()

        secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
        decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)
        hexMatched = decrypted == testString

        secretsObject = await secUtl.asymmetricEncryptBytes(testString, publicKeyBytes)
        decrypted = await secUtl.asymmetricDecryptBytes(secretsObject, secretKeyBytes)
        bytesMatched = decrypted == testString

        # secretsObject = await secUtl.asymmetricEncryptOld(testString, publicKeyHex)
        # decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)
        # console.log("hello 1! "+(decrypted == testString))
        # secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
        # decrypted = await secUtl.asymmetricDecryptOld(secretsObject, secretKeyHex)
        # console.log("hello 2! "+(decrypted == testString))

        if(hexMatched and bytesMatched)
            success = true

            c = count
            before = performance.now()
            while(c--)
                secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
                decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)

            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--)
                secretsObject = await secUtl.asymmetricEncryptBytes(testString, publicKeyBytes)
                decrypted = await secUtl.asymmetricDecryptBytes(secretsObject, secretKeyBytes)        

            after = performance.now()
            bytesMS = after - before

            results.testAsymmetricEncryption = {success, hexMS, bytesMS}
        else
            error = "Error: Decrypted did not match original content!"
            results.testAsymmetricEncryption = {error, hexMatched, bytesMatched} 
    catch error
        results.testAsymmetricEncryption = error.message

############################################################
testSalts = ->
    try
        salt = await secUtl.createRandomLengthSalt()
        saltedContent = salt+testString
        content = await secUtl.removeSalt(saltedContent)

        if(content == testString)
            results.testSalts="success"
        else
            results.testSalts="Error: original: "+testString+" doesn't match unsalted: "+content
    catch error
        results.testSalts=error.message





############################################################
testAuthCode = ->
    try
        request1 = {publicKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, nonce: 0, signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        request2 = {authCode: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, data:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

        kpHex = await secUtl.createKeyPairHex()
        alicePrivHex = kpHex.secretKeyHex
        alicePubHex = kpHex.publicKeyHex

        context = "lenny@extensivlyon.coffee/mega-context"

        seedHex = await secUtl.createSharedSecretHashHex(alicePrivHex, alicePubHex, context)
        seedBytes = tbut.hexToBytes(seedHex)
        authCodeHex = await secUtl.authCodeHex(seedHex, request1)
        authCodeBytes = await secUtl.authCodeBytes(seedBytes, request1)
        
        if(authCodeHex != (tbut.bytesToHex(authCodeBytes)))
            throw new Error("Byte version and Hex version did not match!")

        success = true
        hexMS = 0
        bytesMS = 0
        before = 0
        after = 0
        c = 0


        c = count
        before = performance.now()
        while(c--)
            authCodeHex = secUtl.authCode(seedHex, request2)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            authCodeBytes = secUtl.authCodeBytes(seedHex, request2)
        after = performance.now()
        bytesMS = after - before

        results.testAuthCode= {success, hexMS, bytesMS}

    catch error then results.testAuthCode=error.message

############################################################
testSessionKey = ->
    try
        request1 = {publicKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, nonce: 0, signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        request2 = {authCode: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, data:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

        kpHex = await secUtl.createKeyPairHex()
        alicePrivHex = kpHex.secretKeyHex
        alicePubHex = kpHex.publicKeyHex

        context = "lenny@extensivlyon.coffee/mega-context"

        seedHex = await secUtl.createSharedSecretHashHex(alicePrivHex, alicePubHex, context)
        seedBytes = tbut.hexToBytes(seedHex)
        sessionKeyHex = await secUtl.sessionKeyHex(seedHex, request1)
        sessionKeyBytes = await secUtl.sessionKeyBytes(seedBytes, request1)
        
        if(sessionKeyHex != (tbut.bytesToHex(sessionKeyBytes)))
            throw new Error("Byte version and Hex version did not match!")

        testCipher = await secUtl.symmetricEncrypt(testString, sessionKeyHex)
        # testUncipher = await secUtl.symmetricDecryptBytes(testCipher, sessionKeyBytes)
        testUncipher = await secUtl.symmetricDecrypt(testCipher, sessionKeyHex)
        
        if(testUncipher != testString)
            throw new Error("encyption and decryption of testString did not work with our sessionKey!")

        success = true
        hexMS = 0
        bytesMS = 0
        before = 0
        after = 0
        c = 0


        c = count
        before = performance.now()
        while(c--)
            sessionKeyHex = await secUtl.sessionKeyHex(seedHex, request2)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sessionKeyBytes = await secUtl.sessionKeyBytes(seedBytes, request2)
        after = performance.now()
        bytesMS = after - before

        results.testSessionKey= {success, hexMS, bytesMS}

    catch error then results.testSessionKey=error.message


############################################################
testCreateSharedSecretHash = ->
    try
        kpBytes = await secUtl.createKeyPairBytes()
        alicePrivBytes = kpBytes.secretKeyBytes
        alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        bobPrivBytes = kpBytes.secretKeyBytes
        bobPubBytes = kpBytes.publicKeyBytes

        alicePrivHex = tbut.bytesToHex(alicePrivBytes)
        alicePubHex = tbut.bytesToHex(alicePubBytes)
        bobPrivHex = tbut.bytesToHex(bobPrivBytes)
        bobPubHex = tbut.bytesToHex(bobPubBytes)

        context = "test.extensivlyon.coffee/ultra-context"

        sharedSecretAliceHex = await secUtl.createSharedSecretHashHex(alicePrivHex, bobPubHex, context)
        sharedSecretBobHex = await secUtl.createSharedSecretHashHex(bobPrivHex, alicePubHex, context)
        
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        sharedSecretAliceBytes = await secUtl.createSharedSecretHashBytes(alicePrivBytes, bobPubBytes, context)
        sharedSecretBobBytes = await secUtl.createSharedSecretHashBytes(bobPrivBytes, alicePubBytes, context)
        
        if(tbut.bytesToHex(sharedSecretAliceBytes) != tbut.bytesToHex(sharedSecretBobBytes))
            throw new Error("Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: #{sharedSecretAliceBytes}\nsharedSecretBobBytes: #{sharedSecretBobBytes}")
        
        
        compHex = tbut.bytesToHex(sharedSecretBobBytes)
        if(sharedSecretAliceHex != compHex)
            throw new Error("Hex version of Bytes Secret did not match the original Hex version!\ncompHex: #{compHex}\nsharedSecretAliceHex: #{sharedSecretAliceHex}")

        success = true
        before
        after
        hexMS
        bytesMS
        c

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceHex = await secUtl.createSharedSecretHashHex(alicePrivHex, bobPubHex, context)
            sharedSecretBobHex = await secUtl.createSharedSecretHashHex(bobPrivHex, alicePubHex, context)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.createSharedSecretHashBytes(alicePrivBytes, bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.createSharedSecretHashBytes(bobPrivBytes, alicePubBytes, context)
        after = performance.now()
        bytesMS = after - before

        results.createSharedSecretHash = {success, hexMS, bytesMS}

    catch error then results.createSharedSecretHash = error.message


############################################################
testCreateSharedSecretRaw = ->
    try
        kpBytes = await secUtl.createKeyPairBytes()
        alicePrivBytes = kpBytes.secretKeyBytes
        alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        bobPrivBytes = kpBytes.secretKeyBytes
        bobPubBytes = kpBytes.publicKeyBytes

        alicePrivHex = tbut.bytesToHex(alicePrivBytes)
        alicePubHex = tbut.bytesToHex(alicePubBytes)
        bobPrivHex = tbut.bytesToHex(bobPrivBytes)
        bobPubHex = tbut.bytesToHex(bobPubBytes)

        sharedSecretAliceHex = await secUtl.createSharedSecretRawHex(alicePrivHex, bobPubHex)
        sharedSecretBobHex = await secUtl.createSharedSecretRawHex(bobPrivHex, alicePubHex)
        
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        sharedSecretAliceBytes = await secUtl.createSharedSecretRawBytes(alicePrivBytes, bobPubBytes)
        sharedSecretBobBytes = await secUtl.createSharedSecretRawBytes(bobPrivBytes, alicePubBytes)
        
        if(tbut.bytesToHex(sharedSecretAliceBytes) != tbut.bytesToHex(sharedSecretBobBytes))
            throw new Error("Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: #{sharedSecretAliceBytes}\nsharedSecretBobBytes: #{sharedSecretBobBytes}")
        
        
        compHex = tbut.bytesToHex(sharedSecretBobBytes)
        if(sharedSecretAliceHex != compHex)
            throw new Error("Hex version of Bytes Secret did not match the original Hex version!\ncompHex: #{compHex}\nsharedSecretAliceHex: #{sharedSecretAliceHex}")

        success = true
        before
        after
        hexMS
        bytesMS
        c

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceHex = await secUtl.createSharedSecretRawHex(alicePrivHex, bobPubHex)
            sharedSecretBobHex = await secUtl.createSharedSecretRawHex(bobPrivHex, alicePubHex)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.createSharedSecretRawBytes(alicePrivBytes, bobPubBytes)
            sharedSecretBobBytes = await secUtl.createSharedSecretRawBytes(bobPrivBytes, alicePubBytes)
        after = performance.now()
        bytesMS = after - before
        
        results.createSharedSecretRaw = {success, hexMS, bytesMS}

    catch error then results.createSharedSecretRaw = error.message


############################################################
testReferencedSharedSecretHash = ->
    try
        kpBytes = await secUtl.createKeyPairBytes()
        alicePrivBytes = kpBytes.secretKeyBytes
        alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        bobPrivBytes = kpBytes.secretKeyBytes
        bobPubBytes = kpBytes.publicKeyBytes

        alicePrivHex = tbut.bytesToHex(alicePrivBytes)
        alicePubHex = tbut.bytesToHex(alicePubBytes)
        bobPrivHex = tbut.bytesToHex(bobPrivBytes)
        bobPubHex = tbut.bytesToHex(bobPubBytes)

        context = "test.extensivlyon.coffee/ultra-context"

        referencedHex = await secUtl.referencedSharedSecretHashHex(bobPubHex, context)
        referencePointHex = referencedHex.referencePointHex
        sharedSecretAliceHex = referencedHex.sharedSecretHex

        sharedSecretBobHex = await secUtl.createSharedSecretHashHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        referencedBytes = await secUtl.referencedSharedSecretHashBytes(bobPubBytes, context)
        referencePointBytes = referencedBytes.referencePointBytes
        sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        sharedSecretBobBytes = await secUtl.createSharedSecretHashBytes(bobPrivBytes, referencePointBytes, context)
        if(tbut.bytesToHex(sharedSecretAliceBytes) != tbut.bytesToHex(sharedSecretBobBytes))
            throw new Error("Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: #{sharedSecretAliceBytes}\nsharedSecretBobBytes: #{sharedSecretBobBytes}")    
    
        success = true
        before
        after
        hexMS
        bytesMS
        c

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceHex = await secUtl.referencedSharedSecretHashHex(bobPubHex, context)
            sharedSecretBobHex = await secUtl.referencedSharedSecretHashHex(alicePubHex, context)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.referencedSharedSecretHashBytes(bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.referencedSharedSecretHashBytes(alicePubBytes, context)
        after = performance.now()
        bytesMS = after - before
    
        results.referencedSharedSecretHash = {success, hexMS, bytesMS}

    catch error then results.referencedSharedSecretHash = error.message


############################################################
testReferencedSharedSecretRaw = ->
    try
        kpBytes = await secUtl.createKeyPairBytes()
        alicePrivBytes = kpBytes.secretKeyBytes
        alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        bobPrivBytes = kpBytes.secretKeyBytes
        bobPubBytes = kpBytes.publicKeyBytes

        alicePrivHex = tbut.bytesToHex(alicePrivBytes)
        alicePubHex = tbut.bytesToHex(alicePubBytes)
        bobPrivHex = tbut.bytesToHex(bobPrivBytes)
        bobPubHex = tbut.bytesToHex(bobPubBytes)

        context = "test.extensivlyon.coffee/ultra-context"

        referencedHex = await secUtl.referencedSharedSecretRawHex(bobPubHex, context)
        referencePointHex = referencedHex.referencePointHex
        sharedSecretAliceHex = referencedHex.sharedSecretHex

        sharedSecretBobHex = await secUtl.createSharedSecretRawHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        referencedBytes = await secUtl.referencedSharedSecretRawBytes(bobPubBytes, context)
        referencePointBytes = referencedBytes.referencePointBytes
        sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        sharedSecretBobBytes = await secUtl.createSharedSecretRawBytes(bobPrivBytes, referencePointBytes, context)
        if(tbut.bytesToHex(sharedSecretAliceBytes) != tbut.bytesToHex(sharedSecretBobBytes))
            throw new Error("Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: #{sharedSecretAliceBytes}\nsharedSecretBobBytes: #{sharedSecretBobBytes}")
        
        success = true
        before
        after
        hexMS
        bytesMS
        c

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceHex = await secUtl.referencedSharedSecretRawHex(bobPubHex, context)
            sharedSecretBobHex = await secUtl.referencedSharedSecretRawHex(alicePubHex, context)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.referencedSharedSecretRawBytes(bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.referencedSharedSecretRawBytes(alicePubBytes, context)
        after = performance.now()
        bytesMS = after - before
        results.referencedSharedSecretRaw = {success, hexMS, bytesMS}

    catch error then results.referencedSharedSecretRaw = error.message



#endregion


############################################################
# thingy-byte-uitils tests
but = tbut
array = new Uint8Array(10)
array.fill(32)
array[9] = 42
hex = but.bytesToHex(array)
text = "HelloWörld!"


testBytesToBigInt = ->
    bigInt = but.bytesToBigInt(array.reverse()) # ??? what
    hexProduced = BigInt("0x"+hex) 
    bitIntString = bigInt.toString()
    hexProducedString = hexProduced.toString()
    if bigInt == hexProduced
        success = true
        results.testBytesToBigInt = {success, bitIntString, hexProducedString}
    else
        error = true
        results.testBytesToBigInt = {error, bitIntString, hexProducedString}

    return

testBytesToUtf8 = ->
    textBytes = but.utf8ToBytes(text)
    newstring = but.bytesToUtf8(textBytes)
    if text == newstring
        success = true
        results.testBytesToUtf8 = {success, text, newstring}
    else
        error = true
        results.testBytesToUtf8 = {error, text, newstring}
    return

testBytesToHex = ->
    arrayBuffer = array.buffer
    hexArrayBuffer = but.bytesToHex(arrayBuffer)
    hexArray = but.bytesToHex(array)

    if hexArrayBuffer == hexArray
        success = true
        results.testBytesToHex = {success, hexArray, hexArrayBuffer, array}
    else
        error = true
        results.testBytesToHex = {error, hexArray, hexArrayBuffer, array}
    return

    return

testUtf8ToBytes = ->
    arrayString = but.bytesToUtf8(array)
    textBytes = but.utf8ToBytes(arrayString)
    if JSON.stringify(textBytes) == JSON.stringify(array)
        success = true
        results.testUtf8ToBytes = {success, array, textBytes}
    else
        error = true
        results.testUtf8ToBytes = {error, array, textBytes}
    return

testHexToBytes = ->
    hexBytes = but.hexToBytes(hex)
    if JSON.stringify(hexBytes) == JSON.stringify(array)
        success = true
        results.testHexToBytes = {success, array, hexBytes}
    else
        error = true
        results.testHexToBytes = {error, array, hexBytes}
    return

#endregion