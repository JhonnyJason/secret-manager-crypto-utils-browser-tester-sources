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

    testBytesToBigInt()
    testBytesToUtf8()
    testBytesToHex()
    testUtf8ToBytes()
    testHexToBytes()

    await testShas()
    await testSignatures()
    await testsymmetricEncryption()
    await testAsymmetricEncryption()
    await testSalts() # success

    evaluate()

evaluate = -> 
    console.log(JSON.stringify(results, null, 4))


############################################################
#region secret-manager-crypto-utils tests
import * as secUtl from "./cryptoutilsbrowser"
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

#endregion


############################################################
# thingy-byte-uitils tests
import * as but from "./byteutilsbrowser"

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
        results.testHExToBytes = {success, array, hexBytes}
    else
        error = true
        results.testHexToBytes = {error, array, hexBytes}
    return

#endregion