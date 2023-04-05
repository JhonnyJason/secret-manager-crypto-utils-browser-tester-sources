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
    await testSignatures() # let this run first to ignore performance regressions straight after startup
    
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

    await testDiffieHellmanSecretHash()
    await testDiffieHellmanSecretRaw()
    await testElGamalSecretHash()
    await testElGamalSecretRaw()

    await testSalts() # success


    evaluate()


evaluate = ->
    console.log(JSON.stringify(results, null, 4))


############################################################
#region secret-manager-crypto-utils tests
import * as secUtl from "./browser"
import * as tbut from "thingy-byte-utils"

results = {}
testString = "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^"
count = 1000

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
                decrypted = await secUtl.symmetricDecryptHex(gibbrishHex, keyHex)
            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--)
                gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
                decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)
            after = performance.now()
            bytesMS = after - before

            results.testSymmetricEncryption = {success, hexMS, bytesMS}
        else
            error = "Error: Decrypted did not match original content!"
            results.testSymmetricEncryption = {error, testString, decrypted}
    catch error
        results.testSymmetricEncryption = error.message

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
testDiffieHellmanSecretHash = ->
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

        sharedSecretAliceHex = await secUtl.diffieHellmanSecretHashHex(alicePrivHex, bobPubHex, context)
        sharedSecretBobHex = await secUtl.diffieHellmanSecretHashHex(bobPrivHex, alicePubHex, context)
        
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        sharedSecretAliceBytes = await secUtl.diffieHellmanSecretHashBytes(alicePrivBytes, bobPubBytes, context)
        sharedSecretBobBytes = await secUtl.diffieHellmanSecretHashBytes(bobPrivBytes, alicePubBytes, context)
        
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
            sharedSecretAliceHex = await secUtl.diffieHellmanSecretHashHex(alicePrivHex, bobPubHex, context)
            sharedSecretBobHex = await secUtl.diffieHellmanSecretHashHex(bobPrivHex, alicePubHex, context)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.diffieHellmanSecretHashBytes(alicePrivBytes, bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.diffieHellmanSecretHashBytes(bobPrivBytes, alicePubBytes, context)
        after = performance.now()
        bytesMS = after - before

        results.diffieHellmanSecretHash = {success, hexMS, bytesMS}

    catch error then results.diffieHellmanSecretHash = error.message

############################################################
testDiffieHellmanSecretRaw = ->
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

        sharedSecretAliceHex = await secUtl.diffieHellmanSecretRawHex(alicePrivHex, bobPubHex)
        sharedSecretBobHex = await secUtl.diffieHellmanSecretRawHex(bobPrivHex, alicePubHex)
        
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        sharedSecretAliceBytes = await secUtl.diffieHellmanSecretRawBytes(alicePrivBytes, bobPubBytes)
        sharedSecretBobBytes = await secUtl.diffieHellmanSecretRawBytes(bobPrivBytes, alicePubBytes)
        
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
            sharedSecretAliceHex = await secUtl.diffieHellmanSecretRawHex(alicePrivHex, bobPubHex)
            sharedSecretBobHex = await secUtl.diffieHellmanSecretRawHex(bobPrivHex, alicePubHex)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.diffieHellmanSecretRawBytes(alicePrivBytes, bobPubBytes)
            sharedSecretBobBytes = await secUtl.diffieHellmanSecretRawBytes(bobPrivBytes, alicePubBytes)
        after = performance.now()
        bytesMS = after - before
        
        results.diffieHellmanSecretRaw = {success, hexMS, bytesMS}

    catch error then results.diffieHellmanSecretRaw = error.message

############################################################
testElGamalSecretHash = ->
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

        referencedHex = await secUtl.elGamalSecretHashHex(bobPubHex, context)
        referencePointHex = referencedHex.referencePointHex
        sharedSecretAliceHex = referencedHex.sharedSecretHex

        sharedSecretBobHex = await secUtl.diffieHellmanSecretHashHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        referencedBytes = await secUtl.elGamalSecretHashBytes(bobPubBytes, context)
        referencePointBytes = referencedBytes.referencePointBytes
        sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        sharedSecretBobBytes = await secUtl.diffieHellmanSecretHashBytes(bobPrivBytes, referencePointBytes, context)
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
            sharedSecretAliceHex = await secUtl.elGamalSecretHashHex(bobPubHex, context)
            sharedSecretBobHex = await secUtl.elGamalSecretHashHex(alicePubHex, context)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.elGamalSecretHashBytes(bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.elGamalSecretHashBytes(alicePubBytes, context)
        after = performance.now()
        bytesMS = after - before
    
        results.elGamalSecretHash = {success, hexMS, bytesMS}

    catch error then results.elGamalSecretHash = error.message

############################################################
testElGamalSecretRaw = ->
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

        referencedHex = await secUtl.elGamalSecretRawHex(bobPubHex, context)
        referencePointHex = referencedHex.referencePointHex
        sharedSecretAliceHex = referencedHex.sharedSecretHex

        sharedSecretBobHex = await secUtl.diffieHellmanSecretRawHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex)
            throw new Error("Hex Shared Secrets did not match!\n sharedSecretAliceHex: #{sharedSecretAliceHex}\nsharedSecretBobHex: #{sharedSecretBobHex}")


        referencedBytes = await secUtl.elGamalSecretRawBytes(bobPubBytes, context)
        referencePointBytes = referencedBytes.referencePointBytes
        sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        sharedSecretBobBytes = await secUtl.diffieHellmanSecretRawBytes(bobPrivBytes, referencePointBytes, context)
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
            sharedSecretAliceHex = await secUtl.elGamalSecretRawHex(bobPubHex, context)
            sharedSecretBobHex = await secUtl.elGamalSecretRawHex(alicePubHex, context)
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--)
            sharedSecretAliceBytes = await secUtl.elGamalSecretRawBytes(bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.elGamalSecretRawBytes(alicePubBytes, context)
        after = performance.now()
        bytesMS = after - before
        results.elGamalSecretRaw = {success, hexMS, bytesMS}

    catch error then results.elGamalSecretRaw = error.message

############################################################
testSalts = ->
    try

        content = testString
        saltedContent = secUtl.saltContent(content)
        unsaltedContent = secUtl.unsaltContent(saltedContent)
                
        if(content == unsaltedContent)
            success = true
            c = count
            before = performance.now()
            while(c--)
                saltedContent = secUtl.saltContent(content)
                unsaltedContent = secUtl.unsaltContent(saltedContent)
                if(content != unsaltedContent)
                    console.log(JSON.stringify(Uint8Array.from(saltedContent)))
                    console.log("unsaltedContent: "+unsaltedContent)
                    throw new Error("Error on NewSalt: Unsalted content did not match original content!")
                
            after = performance.now()
            saltMS = after - before

            results.testSalts = {success, saltMS}        
        
        else
            error = "Error: Unsalted content did not match original content!"
            unsaltedContent = Uint8Array.from(unsaltedContent)
            results.testSalts = {error, content, unsaltedContent} 
        
        # salt = await secUtl.createRandomLengthSalt()
        # saltedContent = salt+testString
        # content = await secUtl.removeSalt(saltedContent)

        # if(content == testString)
        #     results.testSalts="success"
        # else
        #     results.testSalts="Error: original: "+testString+" doesn't match unsalted: "+content
    catch error
        results.testSalts=error.message

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