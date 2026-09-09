#    peepdf-3 is a tool to analyse and modify PDF files
#    https://github.com/digitalsleuth/peepdf-3
#    Original Author: Jose Miguel Esparza <jesparza AT eternal-todo.com>
#    Updated for Python 3 by Corey Forman (digitalsleuth - https://github.com/digitalsleuth/peepdf-3)
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf-3.
#
#        peepdf-3 is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf-3 is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf-3. If not, see <http://www.gnu.org/licenses/>.

"""
Module to manage cryptographic operations with PDF files
"""

import hashlib
import struct
import random
import warnings
import sys
from itertools import cycle
from aespython import key_expander, aes_cipher, cbc_mode

warnings.filterwarnings("ignore")

paddingString = b"\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56\xff\xfa\x01\x08\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c\xa9\xfe\x64\x53\x69\x7a"


def computeEncryptionKey(
    password: bytes,
    dictOwnerPass: bytes,
    dictUserPass: str,
    dictOE: str,
    dictUE: str,
    fileID: bytes,
    pElement: int,
    dictKeyLength: int = 128,
    revision: int = 3,
    encryptMetadata: bool = False,
    passwordType=None,
):
    """
    Compute an encryption key to encrypt/decrypt the PDF file

    @param password: The password entered by the user
    @param dictOwnerPass: The owner password from the standard security handler dictionary
    @param dictUserPass: The user password from the standard security handler dictionary
    @param dictOE: The owner encrypted string from the standard security handler dictionary
    @param dictUE:The user encrypted string from the standard security handler dictionary
    @param fileID: The /ID element in the trailer dictionary of the PDF file
    @param pElement: The /P element of the Encryption dictionary
    @param dictKeyLength: The length of the key
    @param revision: The algorithm revision
    @param encryptMetadata: A boolean extracted from the standard security handler dictionary to specify if it's necessary to encrypt the document metadata or not
    @param passwordType: It specifies the given password type. It can be 'USER', 'OWNER' or None.
    @return: A tuple (status,statusContent), where statusContent is the encryption key in case status = 0 or an error message in case status = -1
    """
    try:
        ret = None
        if revision not in {5, 6}:
            keyLength = int(dictKeyLength / 8)
            lenPass = len(password)
            if lenPass > 32:
                password = password[:32]
            elif lenPass < 32:
                password += paddingString[: 32 - lenPass]
            md5input = (
                password + dictOwnerPass + struct.pack("<i", int(pElement)) + fileID
            )
            if revision > 3 and not encryptMetadata:
                md5input += b"\xff" * 4
            key = hashlib.md5(md5input).digest()
            if revision > 2:
                counter = 0
                while counter < 50:
                    key = hashlib.md5(key[:keyLength]).digest()
                    counter += 1
                key = key[:keyLength]
            elif revision == 2:
                key = key[:5]
            return (0, key)
        if passwordType == "USER":
            password = password[:127]
            kSalt = dictUserPass[40:48]
            if revision == 6:
                intermediateKey = computeHardenedHash(password, kSalt)
            else:            
                intermediateKey = hashlib.sha256(password + kSalt).digest()
            ret = decryptData(b"\0" * 16 + dictUE, intermediateKey)
        elif passwordType == "OWNER":
            password = password[:127]
            kSalt = dictOwnerPass[40:48]
            if revision == 6:
                intermediateKey = computeHardenedHash(password, kSalt, dictUserPass)
            else:            
                intermediateKey = hashlib.sha256(password + kSalt + dictUserPass).digest()
            ret = decryptData(b"\0" * 16 + dictOE, intermediateKey)
        return ret
    except:
        return (
            -1,
            f"ComputeEncryptionKey error: {str(sys.exc_info()[0])} {str(sys.exc_info()[1])}",
        )


def computeObjectKey(
    thisId: int,
    generationNum: int,
    encryptionKey: bytes,
    keyLengthBytes: int,
    algorithm: str = "RC4",
):
    """
    Compute the key necessary to encrypt each object, depending on the id and generation number. Only necessary with /V < 5.

    @param thisId: The object id
    @param generationNum: The generation number of the object
    @param encryptionKey: The encryption key
    @param keyLengthBytes: The length of the encryption key in bytes
    @param algorithm: The algorithm used in the encryption/decryption process
    @return A tuple (status,statusContent), where statusContent is the computed key in case status = 0 or an error message in case status = -1
    """
    try:
        key = (
            encryptionKey
            + struct.pack("<i", thisId)[:3]
            + struct.pack("<i", generationNum)[:2]
        )
        if algorithm == "AES":
            key += b"\x73\x41\x6c\x54"
        key = hashlib.md5(key).digest()
        if keyLengthBytes + 5 < 16:
            key = key[: keyLengthBytes + 5]
        else:
            key = key[:16]
        # AES: block size = 16 bytes, initialization vector (16 bytes), random, first bytes encrypted string
        return (0, key)
    except:
        return (
            -1,
            f"ComputeObjectKey error: {str(sys.exc_info()[0])} {str(sys.exc_info()[1])}",
        )


def computeOwnerPass(
    ownerPassString: str, userPassString: str, keyLength: int = 128, revision: int = 3
):
    """
    Compute the owner password necessary to compute the encryption key of the PDF file

    @param ownerPassString: The owner password entered by the user
    @param userPassString: The user password entered by the user
    @param keyLength: The length of the key
    @param revision: The algorithm revision
    @return A tuple (status,statusContent), where statusContent is the computed password in case status = 0 or an error message in case status = -1
    """
    try:
        keyLength = int(keyLength / 8)
        lenPass = len(ownerPassString)
        if lenPass > 32:
            ownerPassString = ownerPassString[:32]
        elif lenPass < 32:
            ownerPassString += paddingString[: 32 - lenPass]
        rc4Key = hashlib.md5(ownerPassString).digest()
        if revision > 2:
            counter = 0
            while counter < 50:
                rc4Key = hashlib.md5(rc4Key).digest()
                counter += 1
        rc4Key = rc4Key[:keyLength]
        lenPass = len(userPassString)
        if lenPass > 32:
            userPassString = userPassString[:32]
        elif lenPass < 32:
            userPassString += paddingString[: 32 - lenPass]
        ownerPass = RC4(userPassString, rc4Key)
        if revision > 2:
            counter = 1
            while counter <= 19:
                newKeyChars = [chr(eachChar ^ counter) for eachChar in rc4Key]
                ownerPass = RC4(ownerPass, "".join(newKeyChars))
                counter += 1
        return (0, ownerPass)
    except:
        return (
            -1,
            f"ComputeOwnerPass error: {str(sys.exc_info()[0])} {str(sys.exc_info()[1])}",
        )


def computeUserPass(
    userPassString: str,
    dictO,
    fileID,
    pElement,
    keyLength: int = 128,
    revision: int = 3,
    encryptMetadata: bool = False,
):
    """
    Compute the user password of the PDF file

    @param userPassString: The user password entered by the user
    @param fileID: The /ID element in the trailer dictionary of the PDF file
    @param pElement: The /P element of the /Encryption dictionary
    @param keyLength: The length of the key
    @param revision: The algorithm revision
    @param encryptMetadata: A boolean extracted from the standard security handler dictionary to specify if it's necessary to encrypt the document metadata or not
    @return: A tuple (status,statusContent), where statusContent is the computed password in case status = 0 or an error message in case status = -1
    """
    userPass = ""
    dictU = ""
    dictOE = ""
    dictUE = ""
    ret = computeEncryptionKey(
        userPassString,
        dictO,
        dictU,
        dictOE,
        dictUE,
        fileID,
        pElement,
        keyLength,
        revision,
        encryptMetadata,
    )
    if ret[0] != -1:
        rc4Key = ret[1]
    else:
        return ret
    try:
        if revision == 2:
            userPass = RC4(paddingString, rc4Key)
        elif revision > 2:
            counter = 1
            md5Input = paddingString + fileID
            hashResult = hashlib.md5(md5Input).digest()
            userPass = RC4(hashResult, rc4Key)
            while counter <= 19:
                newKeyChars = [chr(eachChar ^ counter) for eachChar in rc4Key]
                userPass = RC4(userPass, "".join(newKeyChars))
                counter += 1
            paddingChars = "".join(chr(random.randint(32, 255)) for _ in range(16))
            if isinstance(userPass, bytes):
                userPass += paddingChars.encode("latin-1")
            else:
                userPass += paddingChars
        else:
            # This should not be possible or the PDF specification does not say anything about it
            return (-1, f"ComputeUserPass error: revision number is < 2 ({revision})")
        return (0, userPass)
    except:
        return (
            -1,
            f"ComputeUserPass error: {str(sys.exc_info()[0])} {str(sys.exc_info()[1])}",
        )


def isUserPass(password, computedUserPass, dictU, revision):
    """
    Checks if the given password is the User password of the file

    @param password: The given password or the empty password
    @param computedUserPass: The computed user password of the file
    @param dictU: The /U element of the /Encrypt dictionary
    @param revision: The number of revision of the standard security handler
    @return The boolean telling if the given password is the user password or not
    """

    if revision in {5, 6}:
        vSalt = dictU[32:40]
        if revision == 6:
            inputHash = computeHardenedHash(password, vSalt)
        else:
            inputHash = hashlib.sha256(password + vSalt).digest()
        return bool(inputHash == dictU[:32])        
    if revision in {3, 4}:
        return bool(computedUserPass[:16] == dictU[:16])
    if revision < 3:
        return bool(computedUserPass == dictU)


def isOwnerPass(password, dictO, dictU, keyLength, revision, fileId, pElement, encryptMetadata):
    """
    Checks if the given password is the owner password of the file

    @param password: The given password or the empty password
    @param dictO: The /O element of the /Encrypt dictionary
    @param dictU: The /U element of the /Encrypt dictionary
    @param keyLength: The length of the key
    @param revision: The algorithm revision
    @param fileId: The /ID element in the trailer dictionary of the PDF file
    @param pElement: The /P element of the /Encrypt dictionary
    @param encryptMetadata: A boolean specifying if the document metadata must be encrypted
    @return The boolean telling if the given password is the owner password or not
    """
    if revision in {5, 6}:
        vSalt = dictO[32:40]
        if revision == 6:
            inputHash = computeHardenedHash(password, vSalt, dictU)
        else:
            inputHash = hashlib.sha256(password + vSalt + dictU).digest()
        return bool(inputHash == dictO[:32])
    keyLengthBytes = int(keyLength / 8)
    lenPass = len(password)
    if lenPass > 32:
        password = password[:32]
    elif lenPass < 32:
        password += paddingString[: 32 - lenPass]
    rc4Key = hashlib.md5(password).digest()
    if revision > 2:
        counter = 0
        while counter < 50:
            rc4Key = hashlib.md5(rc4Key).digest()
            counter += 1
    rc4Key = rc4Key[:keyLengthBytes]
    if revision == 2:
        candidateUserPass = RC4(dictO, rc4Key)
    elif revision > 2:
        decryptedO = dictO
        counter = 19
        while counter >= 0:
            newKeyChars = [chr(eachChar ^ counter) for eachChar in rc4Key]
            decryptedO = RC4(decryptedO, "".join(newKeyChars))
            counter -= 1
        candidateUserPass = decryptedO
    else:
        candidateUserPass = ""
    ret = computeUserPass(
        candidateUserPass, dictO, fileId, pElement, keyLength, revision, encryptMetadata
    )
    if ret[0] == -1:
        return False
    recomputedUserPass = ret[1]
    return isUserPass(candidateUserPass, recomputedUserPass, dictU, revision)


def RC4(data, key):
    """
    RC4 implementation

    @param data: Bytes to be encrypyed/decrypted
    @param key: Key used for the algorithm
    @return: The encrypted/decrypted bytes
    """
    y = 0
    hashValue = {}
    box = {}

    # Initialization
    if not isinstance(key, bytes):
        key = key.encode("latin-1")
    if not isinstance(data, bytes):
        data = data.encode("latin-1")
    keyLength = len(key)
    dataLength = len(data)
    for x in range(256):
        hashValue[x] = key[x % keyLength]
        box[x] = x
    for x in range(256):
        y = (y + int(box[x]) + int(hashValue[x])) % 256
        tmp = box[x]
        box[x] = box[y]
        box[y] = tmp

    z = y = 0
    ret = bytearray(dataLength)
    for x in range(0, dataLength):
        z = (z + 1) % 256
        y = (y + box[z]) % 256
        tmp = box[z]
        box[z] = box[y]
        box[y] = tmp
        k = box[((box[z] + box[y]) % 256)]
        ret[x] = data[x] ^ k
    return bytes(ret)


def xor(byteVal, key):
    """
    Simple XOR implementation
    Author: Evan Fosmark (http://www.evanfosmark.com/2008/06/xor-encryption-with-python/)
    @param byteVal: Bytes to be xored
    @param key: Key used for the operation, it's cycled.
    @return: The xored bytes
    """
    key = cycle(key)
    return "".join(chr(ord(x) ^ ord(y)) for (x, y) in zip(byteVal, key))


def decryptData(data, password=None, keyLength=None, mode="CBC"):
    """
    Created from the demonstration of the pythonaes package.

    Copyright (c) 2010, Adam Newman http://www.caller9.com/
    Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
    """
    decryptedData = ""
    aesMode = None
    if keyLength is None:
        keyLength = len(password) * 8
    if keyLength not in {128, 192, 256}:
        return (-1, "Bad length key in AES decryption process")
    try:
        iv = [ord(x) for x in data[:16]]
    except:
        iv = list(data[:16])
    try:
        key = [ord(x) for x in password]
    except:
        key = list(password)
    data = data[16:]
    if len(data) % 16 != 0:
        data = data[: -(len(data) % 16)]
    keyExpander = key_expander.KeyExpander(keyLength)
    expandedKey = keyExpander.expand(key)
    aesCipher = aes_cipher.AESCipher(expandedKey)
    if mode == "CBC":
        aesMode = cbc_mode.CBCMode(aesCipher, 16)
    aesMode.set_iv(iv)
    for i in range(0, len(data), 16):
        try:
            ciphertext = [ord(x) for x in data[i : i + 16]]
        except:
            ciphertext = list(data[i : i + 16])
        decryptedBytes = aesMode.decrypt_block(ciphertext)
        for byte in decryptedBytes:
            decryptedData += chr(byte)
    return (0, decryptedData)


def encryptData(data, password=None, keyLength=None, mode="CBC"):
    """
    AES encryption, generates a random 16-byte IV, pads the plaintext to
    a multiple of the block size (a full block of padding is added even if
    already aligned, as per PDF specs use of PKCS#5 padding).
    Returns iv plus ciphertext.
    """
    if keyLength is None:
        keyLength = len(password) * 8
    if keyLength not in {128, 192, 256}:
        return (-1, "Bad length key in AES encryption process")
    try:
        key = [ord(x) for x in password]
    except (TypeError, IndexError):
        key = list(password)
    iv = [random.randint(0, 255) for _ in range(16)]
    padLength = 16 - (len(data) % 16)
    if isinstance(data, bytes):
        data = data + bytes([padLength]) * padLength
    else:
        data = data + chr(padLength) * padLength
    keyExpander = key_expander.KeyExpander(keyLength)
    expandedKey = keyExpander.expand(key)
    aesCipher = aes_cipher.AESCipher(expandedKey)
    aesMode = None
    if mode == "CBC":
        aesMode = cbc_mode.CBCMode(aesCipher, 16)
    aesMode.set_iv(iv)
    encryptedData = "".join(chr(b) for b in iv)
    for i in range(0, len(data), 16):
        try:
            plaintext = [ord(x) for x in data[i : i + 16]]
        except (TypeError, IndexError):
            plaintext = list(data[i : i + 16])
        encryptedBlock = aesMode.encrypt_block(plaintext)
        for byte in encryptedBlock:
            encryptedData += chr(byte)
    return (0, encryptedData)


def _aesRawCbc(data: bytes, key: bytes, iv: bytes, encrypt: bool = True) -> bytes:
    """
    Raw AES-CBC with no padding and an explicit IV.
    Used for AESV3 (/R 6).

    @param data: Plaintext or ciphertext, already a multiple of 16 bytes.
    @param key: 128, 192 or 256-bit AES key.
    @param iv: 16-byte IV.
    @return: The transformed bytes (same length as data).
    """
    keyExpander = key_expander.KeyExpander(len(key) * 8)
    expandedKey = keyExpander.expand(list(key))
    aesCipher = aes_cipher.AESCipher(expandedKey)
    aesMode = cbc_mode.CBCMode(aesCipher, 16)
    aesMode.set_iv(list(iv))
    result = bytearray()
    for i in range(0, len(data), 16):
        block = list(data[i : i + 16])
        outBlock = aesMode.encrypt_block(block) if encrypt else aesMode.decrypt_block(block)
        result.extend(outBlock)
    return bytes(result)


def _aesEcbEncryptBlock(block: bytes, key: bytes) -> bytes:
    """
    Encrypts a single 16-byte block with raw AES-ECB (no chaining, no padding).
    """
    keyExpander = key_expander.KeyExpander(len(key) * 8)
    expandedKey = keyExpander.expand(list(key))
    aesCipher = aes_cipher.AESCipher(expandedKey)
    return bytes(aesCipher.cipher_block(list(block)))


def computeHardenedHash(password: bytes, salt: bytes, userKeyData: bytes = b"") -> bytes:
    """
    @param password: The UTF-8 encoded password (up to 127 bytes).
    @param salt: The 8-byte validation or key salt.
    @param userKeyData: The 48-byte /U value; empty for user-related hashes, required for owner-related ones (per spec).
    """
    key = hashlib.sha256(password + salt + userKeyData).digest()
    roundNum = 0
    while True:
        k1 = (password + key + userKeyData) * 64
        e = _aesRawCbc(k1, key[:16], key[16:32], encrypt=True)
        checksum = sum(e[:16]) % 3
        if checksum == 0:
            key = hashlib.sha256(e).digest()
        elif checksum == 1:
            key = hashlib.sha384(e).digest()
        else:
            key = hashlib.sha512(e).digest()
        roundNum += 1
        if roundNum >= 64 and e[-1] <= roundNum - 32:
            break
    return key[:32]


def computeUserPassAESV3(password: bytes, fileEncryptionKey: bytes):
    """
    @return: A tuple (status, statusContent), where statusContent is
        (U, UE), 48 and 32 bytes respectively, in case status = 0, or
        an error message in case status = -1.
    """
    try:
        password = password[:127]
        validationSalt = bytes(random.randint(0, 255) for _ in range(8))
        keySalt = bytes(random.randint(0, 255) for _ in range(8))
        validationHash = computeHardenedHash(password, validationSalt)
        u = validationHash + validationSalt + keySalt
        intermediateKey = computeHardenedHash(password, keySalt)
        ue = _aesRawCbc(fileEncryptionKey, intermediateKey, b"\x00" * 16, encrypt=True)
        return (0, (u, ue))
    except Exception as exc:
        return (-1, f"ComputeUserPassAESV3 error: {exc}")


def computeOwnerPassAESV3(password: bytes, fileEncryptionKey: bytes, dictU: bytes):
    """
    @param dictU: The full 48-byte /U value already computed.
    @return: A tuple (status, statusContent), where statusContent is
        (O, OE), 48 and 32 bytes respectively, in case status = 0, or
        an error message in case status = -1.
    """
    try:
        password = password[:127]
        validationSalt = bytes(random.randint(0, 255) for _ in range(8))
        keySalt = bytes(random.randint(0, 255) for _ in range(8))
        validationHash = computeHardenedHash(password, validationSalt, dictU)
        o = validationHash + validationSalt + keySalt
        intermediateKey = computeHardenedHash(password, keySalt, dictU)
        oe = _aesRawCbc(fileEncryptionKey, intermediateKey, b"\x00" * 16, encrypt=True)
        return (0, (o, oe))
    except Exception as exc:
        return (-1, f"ComputeOwnerPassAESV3 error: {exc}")


def computePermsAESV3(permissionNum: int, encryptMetadata: bool, fileEncryptionKey: bytes):
    """
    Computes the /Perms value for a new revision 6 (AESV3) encrypted file.
    @return: A tuple (status, statusContent), where statusContent is the
        16-byte /Perms value in case status = 0, or an error message in
        case status = -1.
    """
    try:
        block = struct.pack("<i", permissionNum) + b"\xff\xff\xff\xff"
        block += b"T" if encryptMetadata else b"F"
        block += b"adb"
        block += bytes(random.randint(0, 255) for _ in range(4))
        return (0, _aesEcbEncryptBlock(block, fileEncryptionKey))
    except Exception as exc:
        return (-1, f"ComputePermsAESV3 error: {exc}")