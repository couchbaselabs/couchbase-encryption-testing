/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.encryption.errors.DecryptionFailureException;
import com.couchbase.client.java.json.JsonObject;
import com.couchbase.client.java.json.JsonObjectCrypto;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DefaultCryptoManagerTest extends TestBase {
    public DefaultCryptoManagerTest() throws Exception {
    }

    @Test
    void decryptResultIncorrectAlg() {
        upsertDocument("testDocId", "encryptedFieldName", "encryptedFieldValue");

        JsonObject readItBack = collection.get("testDocId").contentAsObject();
        JsonObject mangledJson = readItBack.getObject("encrypted$encryptedFieldName");
        assertEquals(ALGORITHM, mangledJson.get("alg"));
        mangledJson.put("alg", "IncorrectAlgo");

        JsonObjectCrypto readItBackCrypto = crypto.withObject(readItBack);
        DecryptionFailureException e = assertThrows(DecryptionFailureException.class, () -> {
            readItBackCrypto.getString("encryptedFieldName");
        });
        assertEquals("Decryption failed; Missing decrypter for algorithm 'IncorrectAlgo'", e.getMessage());
    }

    @Test
    void decryptResultMissingAlg() {
        upsertDocument("testDocId", "encryptedFieldName", "encryptedFieldValue");

        JsonObject readItBack = collection.get("testDocId").contentAsObject();
        JsonObject mangledJson = readItBack.getObject("encrypted$encryptedFieldName");
        assertEquals(ALGORITHM, mangledJson.get("alg"));
        mangledJson.removeKey("alg");

        JsonObjectCrypto readItBackCrypto = crypto.withObject(readItBack);
        DecryptionFailureException e = assertThrows(DecryptionFailureException.class, () -> {
            readItBackCrypto.getString("encryptedFieldName");
        });
        assertEquals("Decryption failed; Encryption result is missing algorithm attribute.", e.getMessage());
    }


    @Test
    void decryptResultIncorrectKid() {
        upsertDocument("testDocId", "encryptedFieldName", "encryptedFieldValue");

        JsonObject readItBack = collection.get("testDocId").contentAsObject();
        JsonObject mangledJson = readItBack.getObject("encrypted$encryptedFieldName");
        assertEquals(KEY_ID, mangledJson.get("kid"));
        mangledJson.put("kid", "IncorrectKid");


        JsonObjectCrypto readItBackCrypto = crypto.withObject(readItBack);
        DecryptionFailureException e = assertThrows(DecryptionFailureException.class, () -> {
            readItBackCrypto.getString("encryptedFieldName");
        });
        assertEquals("Decryption failed; Failed to locate crypto key 'IncorrectKid'", e.getMessage());
    }

    @Test
    void decryptResultMissingKid() {
        upsertDocument("testDocId", "encryptedFieldName", "encryptedFieldValue");

        JsonObject readItBack = collection.get("testDocId").contentAsObject();
        JsonObject mangledJson = readItBack.getObject("encrypted$encryptedFieldName");
        assertEquals(KEY_ID, mangledJson.get("kid"));
        mangledJson.removeKey("kid");


        JsonObjectCrypto readItBackCrypto = crypto.withObject(readItBack);
        DecryptionFailureException e = assertThrows(DecryptionFailureException.class, () -> {
            readItBackCrypto.getString("encryptedFieldName");
        });
        assertEquals("Decryption failed; Failed to locate crypto key 'null'", e.getMessage());
    }


    @Test
    void decryptResultMissingDecrypter() {
        try {
            // AES-256 authenticated with HMAC SHA-512. Requires a 64-byte key.
            provider = AeadAes256CbcHmacSha512Provider.builder()
                .keyring(keyring)
                .build();

            cryptoManager = DefaultCryptoManager.builder()
                .defaultEncrypter(provider.encrypterForKey("my-key"))
                .build();
            setup(cryptoManager);

            upsertDocument("testDocId", "encryptedFieldName", "encryptedFieldValue");

            JsonObject readItBack = collection.get("testDocId").contentAsObject();
            JsonObjectCrypto readItBackCrypto = crypto.withObject(readItBack);
            DecryptionFailureException e = assertThrows(DecryptionFailureException.class, () -> {
                readItBackCrypto.getString("encryptedFieldName");
            });
            assertEquals("Decryption failed; Missing decrypter for algorithm 'AEAD_AES_256_CBC_HMAC_SHA512'", e.getMessage());
        } finally {
            setup();
        }
    }
}
