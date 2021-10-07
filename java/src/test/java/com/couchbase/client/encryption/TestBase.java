/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.core.encryption.CryptoManager;
import com.couchbase.client.core.error.IndexExistsException;
import com.couchbase.client.java.Bucket;
import com.couchbase.client.java.Cluster;
import com.couchbase.client.java.ClusterOptions;
import com.couchbase.client.java.Collection;
import com.couchbase.client.java.env.ClusterEnvironment;
import com.couchbase.client.java.json.JsonObject;
import com.couchbase.client.java.json.JsonObjectCrypto;
import com.couchbase.client.java.manager.query.QueryIndexManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TestBase {
    public static final String ALGORITHM = "AEAD_AES_256_CBC_HMAC_SHA512";
    public static final String KEY_ID = "my-key";
    public static final String CLUSTER_CONFIG_JSON = "ClusterConfiguration.json";
    private static final String USER_NAME = "Administrator";
    private static final String PASSWORD = "password";
    private static String clusterHostname = "172.23.111.138";
    Cluster cluster;
    Bucket bucket;
    Collection collection;
    JsonObject document;
    JsonObjectCrypto crypto;
    CryptoManager cryptoManager;
    AeadAes256CbcHmacSha512Provider provider;
    KeyStoreKeyring keyring;


    public TestBase() throws Exception {
        init();
    }

    static void createPrimaryIndex(Cluster cluster, String bucketName) {
        try {
            QueryIndexManager indexManager = cluster.queryIndexes();
            indexManager.createPrimaryIndex(bucketName);
        } catch (IndexExistsException e) {
        }
    }

    private void init() throws Exception {
        readClusterInfo();
        setKeyStore();
        setup();
        createPrimaryIndex(cluster, bucket.name());
    }

    private void readClusterInfo() {
        JsonObject jo;
        try {
            String content = new String(Files.readAllBytes(Paths.get(CLUSTER_CONFIG_JSON)), StandardCharsets.UTF_8);
            jo = JsonObject.fromJson(content);
        } catch (Exception e) {
            System.err.println("Unable to get bucket/cluster details from params file.  Make sure to copy ClusterConfiguration.example.json to " + CLUSTER_CONFIG_JSON + " and customise it to your own cluster.");
            System.exit(-1);
            throw new IllegalStateException("Doesn't get here"); // keeps the IDE happy
        }

        clusterHostname = jo.getString("cluster");
    }

    private void setKeyStore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(null); // initialize new empty key store

        // Generate 64 random bytes
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[64];
        random.nextBytes(keyBytes);

        // Add a new key called "my-key" to the key store
        KeyStoreKeyring.setSecretKey(keyStore, "my-key", keyBytes, "protection-password".toCharArray());

        // Persist  key store to disk to ensure  we can retrieve later if needed
        try (OutputStream os = new FileOutputStream("MyKeystoreFile.jceks")) {
            keyStore.store(os, "integrity-password".toCharArray());
        }

        keyStore = KeyStore.getInstance("JCEKS");
        try (InputStream is = new FileInputStream("MyKeystoreFile.jceks")) {
            keyStore.load(is, "integrity-password".toCharArray());
        }

        KeyStoreKeyring keyring = new KeyStoreKeyring(keyStore, keyName -> "protection-password");

        this.keyring = keyring;

    }

    void setup() {
        // AES-256 authenticated with HMAC SHA-512. Requires a 64-byte key.
        provider = AeadAes256CbcHmacSha512Provider.builder()
            .keyring(keyring)
            .build();


        cryptoManager = DefaultCryptoManager.builder()
            .decrypter(provider.decrypter())
            .defaultEncrypter(provider.encrypterForKey("my-key"))
            .build();

        setup(cryptoManager);
    }

    void setup(CryptoManager cryptoManager) {

        ClusterEnvironment env = ClusterEnvironment.builder()
            .cryptoManager(cryptoManager)
            .build();

        cluster = Cluster.connect(clusterHostname,
            ClusterOptions.clusterOptions(USER_NAME, PASSWORD).environment(env));
        bucket = cluster.bucket("default");
        collection = bucket.defaultCollection();
        document = JsonObject.create();
        crypto = document.crypto(collection);
    }

    public void enableCustomPrefix(String customPrefix) {
        cryptoManager = DefaultCryptoManager.builder()
            .decrypter(provider.decrypter())
            .defaultEncrypter(provider.encrypterForKey("my-key"))
            .encryptedFieldNamePrefix(customPrefix)
            .build();

        ClusterEnvironment env = ClusterEnvironment.builder()
            .cryptoManager(cryptoManager)
            .build();

        cluster = Cluster.connect(clusterHostname,
            ClusterOptions.clusterOptions(USER_NAME, PASSWORD).environment(env));
        bucket = cluster.bucket("default");
        collection = bucket.defaultCollection();
        document = JsonObject.create();
        crypto = document.crypto(collection);
    }

    public void revertToDefaultPrefix() {
        setup();
    }

    public JsonObject upsertDocument(String testDocId, String encryptedFieldName, String encryptedFieldValue) {
        JsonObject document = JsonObject.create();
        JsonObjectCrypto crypto = document.crypto(collection);
        crypto.put(encryptedFieldName, encryptedFieldValue);
        collection.upsert(testDocId, document);
        return document;
    }

    public void validateCustomPrefix(String customPrefix, String testDocId, String encryptedFieldName) {
        JsonObject readItBack = collection.get(testDocId).contentAsObject();
        JsonObject mangledJson = readItBack.getObject(customPrefix + encryptedFieldName);
        assertEquals(ALGORITHM, mangledJson.get("alg"));
        assertEquals(KEY_ID, mangledJson.get("kid"));
        assertNotNull(mangledJson.get("ciphertext"));
    }

    public void insertPartiallyEncryptedDoc(String testDocId) {
        document = JsonObject.create();
        crypto = document.crypto(collection);
        crypto.put("encryptedValue", "This is encrypted Value"); // This fielf will be encrypted
        document.put("unEncrypted", true); // This field will not be encrypted
        collection.upsert(testDocId, document);
    }

}

