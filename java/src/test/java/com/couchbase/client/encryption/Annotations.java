/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.core.encryption.CryptoManager;
import com.couchbase.client.java.encryption.annotation.Encrypted;
import com.couchbase.client.java.json.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Annotations extends TestBase {
    private final Keyring keyring;
    private final CryptoManager cryptoManager;

    public Annotations() throws Exception {
        Map<String, byte[]> keys = new HashMap<>();
        keys.put("defaultKey", fakeKey(64));
        keys.put("nonDefaultKey", fakeKey(64));
        keyring = Keyring.fromMap(keys);

        provider = AeadAes256CbcHmacSha512Provider.builder()
            .keyring(keyring)
            .build();

        cryptoManager = DefaultCryptoManager.builder()
            .decrypter(provider.decrypter())
            .defaultEncrypter(provider.encrypterForKey("defaultKey"))
            .encrypter("nonDefault", provider.encrypterForKey("nonDefaultKey"))
            .build();

        setup(cryptoManager);
    }

    private static byte[] fakeKey(int len) {
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) i;
        }
        return result;
    }

    @Test
    void testAnnotations() {
        AnnotationSample annotationTest = new AnnotationSample();
        annotationTest.setDefaultEncrypter("defaultEncrypter");
        annotationTest.setExplicitlySpecifiedEncrypter("explicitlySpecifiedEncrypter");

        collection.upsert("testDocId", annotationTest);

        JsonObject defaultEncrypter = collection.get("testDocId")
            .contentAsObject()
            .getObject("encrypted$defaultEncrypter");
        assertEquals("defaultKey", defaultEncrypter.get("kid"));

        JsonObject explicitlySpecifiedEncrypter = collection.get("testDocId")
            .contentAsObject()
            .getObject("encrypted$explicitlySpecifiedEncrypter");
        assertEquals("nonDefaultKey", explicitlySpecifiedEncrypter.get("kid"));

    }
}


class AnnotationSample {
    @Encrypted
    private String defaultEncrypter;  // Encryption of this should be done by the default encryoter

    @Encrypted(encrypter = "nonDefault")
    private String explicitlySpecifiedEncrypter;// Encryption of this should be done by the "nonDefault" encrypter


    public void setDefaultEncrypter(String defaultEncrypter) {
        this.defaultEncrypter = defaultEncrypter;
    }

    public void setExplicitlySpecifiedEncrypter(String explicitlySpecifiedEncrypter) {
        this.explicitlySpecifiedEncrypter = explicitlySpecifiedEncrypter;
    }

    public String getDefaultEncrypter() {
        return defaultEncrypter;
    }

    public String getExplicitlySpecifiedEncrypter() {
        return explicitlySpecifiedEncrypter;
    }
}

