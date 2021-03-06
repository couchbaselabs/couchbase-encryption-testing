/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.core.encryption.CryptoManager;
import com.couchbase.client.encryption.errors.DecryptionFailureException;
import com.couchbase.client.java.json.JsonObject;
import com.couchbase.client.java.json.JsonObjectCrypto;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LegacyAesDecrypterTest {
    Keyring keyring;
    CryptoManager cryptoManager;

    // Generated by Java FLE version 1
    JsonObject originalObject = JsonObject.fromJson(
        "{\n" +
            "  \"__crypt_one\": {\n" +
            "    \"sig\": \"TkpyZnha4xd+FsX1aEGqB235d495oOUBfC4Y+Gbic4U=\",\n" +
            "    \"ciphertext\": \"MZI/xSiM7919UTM5CO/RWg==\",\n" +
            "    \"alg\": \"AES-128-HMAC-SHA256\",\n" +
            "    \"iv\": \"HIBdmnoQD4DUgkBj5LAMFw==\",\n" +
            "    \"kid\": \"aes128Key\"\n" +
            "  },\n" +
            "  \"__crypt_two\": {\n" +
            "    \"sig\": \"f0hWVdBM/pEcADl0eKx8Eq/KhP00/2oqXYXTJkt2xhA=\",\n" +
            "    \"ciphertext\": \"biERBQajaRxrfe8mXFqJag==\",\n" +
            "    \"alg\": \"AES-256-HMAC-SHA256\",\n" +
            "    \"iv\": \"03AUmzwQqnbs/JhkWGrIkw==\",\n" +
            "    \"kid\": \"aes256Key\"\n" +
            "  }\n" +
            "}");

    public LegacyAesDecrypterTest() {
        Map<String, byte[]> keys = new HashMap<>();
        keys.put("aes256Key", fakeKey(32));
        keys.put("aes128Key", fakeKey(16));
        keys.put("hmacKey", fakeKey(7));
        keyring = Keyring.fromMap(keys);

        cryptoManager = DefaultCryptoManager.builder()
            .encryptedFieldNamePrefix("__crypt_")
            .legacyAesDecrypters(keyring, keyName -> "hmacKey")
            .build();
    }

    private static byte[] fakeKey(int len) {
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) i;
        }
        return result;
    }

    @Test
    void canDecrypt() {
        JsonObjectCrypto crypto = originalObject.crypto(cryptoManager);
        assertEquals(1, crypto.getInt("one"));
        assertEquals(2, crypto.getInt("two"));
    }

    @Test
    void missingAndIncorrectSig() {
        JsonObject obj = JsonObject.fromJson(
            "{\n" +
                "  \"__crypt_one\": {\n" +
                "    \"ciphertext\": \"MZI/xSiM7919UTM5CO/RWg==\",\n" +
                "    \"alg\": \"AES-128-HMAC-SHA256\",\n" +
                "    \"iv\": \"HIBdmnoQD4DUgkBj5LAMFw==\",\n" +
                "    \"kid\": \"aes128Key\"\n" +
                "  },\n" +
                "  \"__crypt_two\": {\n" +
                "    \"sig\": \"efhWVdBM/pEcADl0eKx8Eq/KhP00/2oqXYXTJkt2xhA=\",\n" +
                "    \"ciphertext\": \"biERBQajaRxrfe8mXFqJag==\",\n" +
                "    \"alg\": \"AES-256-HMAC-SHA256\",\n" +
                "    \"iv\": \"03AUmzwQqnbs/JhkWGrIkw==\",\n" +
                "    \"kid\": \"aes256Key\"\n" +
                "  }\n" +
                "}");
        JsonObjectCrypto crypto = obj.crypto(cryptoManager);

        DecryptionFailureException e1 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("one"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e1.getMessage()); //TODO Should this be sig not found ??

        DecryptionFailureException e2 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("two"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e2.getMessage());
    }

    @Test
    void missingAndIncorrectKid() {
        JsonObject obj = JsonObject.fromJson(
            "{\n" +
                "  \"__crypt_one\": {\n" +
                "    \"sig\": \"TkpyZnha4xd+FsX1aEGqB235d495oOUBfC4Y+Gbic4U=\",\n" +
                "    \"ciphertext\": \"MZI/xSiM7919UTM5CO/RWg==\",\n" +
                "    \"alg\": \"AES-128-HMAC-SHA256\",\n" +
                "    \"iv\": \"HIBdmnoQD4DUgkBj5LAMFw==\"\n" +
                "  },\n" +
                "  \"__crypt_two\": {\n" +
                "    \"sig\": \"f0hWVdBM/pEcADl0eKx8Eq/KhP00/2oqXYXTJkt2xhA=\",\n" +
                "    \"ciphertext\": \"biERBQajaRxrfe8mXFqJag==\",\n" +
                "    \"alg\": \"AES-256-HMAC-SHA256\",\n" +
                "    \"iv\": \"03AUmzwQqnbs/JhkWGrIkw==\",\n" +
                "    \"kid\": \"afs256Key\"\n" +
                "  }\n" +
                "}");
        JsonObjectCrypto crypto = obj.crypto(cryptoManager);

        DecryptionFailureException e1 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("one"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e1.getMessage()); //TODO Should this be sig not found ??

        DecryptionFailureException e2 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("two"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e2.getMessage());//TODO Should this be Kid not match ??

    }

    @Test
    void missingAndIncorrectAlgo() {
        JsonObject obj = JsonObject.fromJson(
            "{\n" +
                "  \"__crypt_one\": {\n" +
                "    \"sig\": \"TkpyZnha4xd+FsX1aEGqB235d495oOUBfC4Y+Gbic4U=\",\n" +
                "    \"ciphertext\": \"MZI/xSiM7919UTM5CO/RWg==\",\n" +
                "    \"iv\": \"HIBdmnoQD4DUgkBj5LAMFw==\",\n" +
                "    \"kid\": \"aes128Key\"\n" +
                "  },\n" +
                "  \"__crypt_two\": {\n" +
                "    \"sig\": \"f0hWVdBM/pEcADl0eKx8Eq/KhP00/2oqXYXTJkt2xhA=\",\n" +
                "    \"ciphertext\": \"biERBQajaRxrfe8mXFqJag==\",\n" +
                "    \"alg\": \"AFS-256-HMAC-SHA256\",\n" +
                "    \"iv\": \"03AUmzwQqnbs/JhkWGrIkw==\",\n" +
                "    \"kid\": \"aes256Key\"\n" +
                "  }\n" +
                "}");
        JsonObjectCrypto crypto = obj.crypto(cryptoManager);


        DecryptionFailureException e1 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("one"); // This one misses the signature
        });
        assertEquals("Decryption failed; Encryption result is missing algorithm attribute.", e1.getMessage());

        DecryptionFailureException e2 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("two"); // This one misses the signature
        });
        assertEquals("Decryption failed; Missing decrypter for algorithm 'AFS-256-HMAC-SHA256'", e2.getMessage());
    }

    @Test
    void missingAndIncorrectIV() {
        JsonObject obj = JsonObject.fromJson(
            "{\n" +
                "  \"__crypt_one\": {\n" +
                "    \"sig\": \"TkpyZnha4xd+FsX1aEGqB235d495oOUBfC4Y+Gbic4U=\",\n" +
                "    \"ciphertext\": \"MZI/xSiM7919UTM5CO/RWg==\",\n" +
                "    \"alg\": \"AES-128-HMAC-SHA256\",\n" +
                "    \"kid\": \"aes128Key\"\n" +
                "  },\n" +
                "  \"__crypt_two\": {\n" +
                "    \"sig\": \"f0hWVdBM/pEcADl0eKx8Eq/KhP00/2oqXYXTJkt2xhA=\",\n" +
                "    \"ciphertext\": \"biERBQajaRxrfe8mXFqJag==\",\n" +
                "    \"alg\": \"AES-256-HMAC-SHA256\",\n" +
                "    \"iv\": \"13AUmzwQqnbs/JhkWGrIkw==\",\n" +
                "    \"kid\": \"aes256Key\"\n" +
                "  }\n" +
                "}");
        JsonObjectCrypto crypto = obj.crypto(cryptoManager);

        DecryptionFailureException e1 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("one"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e1.getMessage()); //TODO Should IV be Kid not found ??

        DecryptionFailureException e2 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("two"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e2.getMessage()); //TODO Should this be IV not match ??
    }

    @Test
    void missingAndIncorrectCiphertext() {
        JsonObject obj = JsonObject.fromJson(
            "{\n" +
                "  \"__crypt_one\": {\n" +
                "    \"sig\": \"TkpyZnha4xd+FsX1aEGqB235d495oOUBfC4Y+Gbic4U=\",\n" +
                "    \"alg\": \"AES-128-HMAC-SHA256\",\n" +
                "    \"iv\": \"HIBdmnoQD4DUgkBj5LAMFw==\",\n" +
                "    \"kid\": \"aes128Key\"\n" +
                "  },\n" +
                "  \"__crypt_two\": {\n" +
                "    \"sig\": \"f0hWVdBM/pEcADl0eKx8Eq/KhP00/2oqXYXTJkt2xhA=\",\n" +
                "    \"ciphertext\": \"aiERBQajaRxrfe8mXFqJag==\",\n" +
                "    \"alg\": \"AES-256-HMAC-SHA256\",\n" +
                "    \"iv\": \"03AUmzwQqnbs/JhkWGrIkw==\",\n" +
                "    \"kid\": \"aes256Key\"\n" +
                "  }\n" +
                "}");
        JsonObjectCrypto crypto = obj.crypto(cryptoManager);

        DecryptionFailureException e1 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("one"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e1.getMessage()); //TODO Should this be Cipher not found ??

        DecryptionFailureException e2 = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("two"); // This one misses the signature
        });
        assertEquals("Decryption failed; Signature does not match.", e2.getMessage()); //TODO Should this be Cipher not match ??
    }

    @Test
    void keyStoreMissingHmacId() {
        Map<String, byte[]> keys = new HashMap<>();
        keys.put("aes256Key", fakeKey(32));
        keys.put("aes128Key", fakeKey(16));
        keyring = Keyring.fromMap(keys);

        cryptoManager = DefaultCryptoManager.builder()
            .encryptedFieldNamePrefix("__crypt_")
            .legacyAesDecrypters(keyring, keyName -> "hmacKey")
            .build();
        JsonObjectCrypto crypto = originalObject.crypto(cryptoManager);

        DecryptionFailureException e = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("one"); // This one misses the signature
        });
        assertEquals("Decryption failed; Failed to locate crypto key 'hmacKey'", e.getMessage());
    }

    @Test
    void keyStoreMissingKid() {
        Map<String, byte[]> keys = new HashMap<>();
        keys.put("someKey", fakeKey(32));
        keys.put("randomKey", fakeKey(16));
        keys.put("hmacKey", fakeKey(7));
        keyring = Keyring.fromMap(keys);

        cryptoManager = DefaultCryptoManager.builder()
            .encryptedFieldNamePrefix("__crypt_")
            .legacyAesDecrypters(keyring, keyName -> "hmacKey")
            .build();
        JsonObjectCrypto crypto = originalObject.crypto(cryptoManager);

        DecryptionFailureException e = assertThrows(DecryptionFailureException.class, () -> {
            crypto.getInt("one"); // This one misses the signature
        });
        assertEquals("Decryption failed; Failed to locate crypto key 'aes128Key'", e.getMessage());
    }


}
