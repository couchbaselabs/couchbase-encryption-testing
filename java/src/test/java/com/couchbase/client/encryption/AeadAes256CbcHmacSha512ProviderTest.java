/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.core.encryption.CryptoManager;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.couchbase.client.core.util.CbCollections.mapOf;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class AeadAes256CbcHmacSha512ProviderTest {
    private final AeadAes256CbcHmacSha512Provider provider;

    public AeadAes256CbcHmacSha512ProviderTest() {
        provider = EncryptionTestHelper.provider();
    }

    @Test
    void encryptAndDecrypt() {
        final byte[] plaintext = "\"The enemy knows the system.\"".getBytes(UTF_8);

        final Map<String, Object> encrypted = mapOf(
            "alg", "AEAD_AES_256_CBC_HMAC_SHA512",
            "kid", "test-key",
            "ciphertext", "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=");

        CryptoManager cryptoManager = DefaultCryptoManager.builder()
            .decrypter(provider.decrypter())
            .defaultEncrypter(provider.encrypterForKey("test-key"))
            .build();

        assertEquals(encrypted, cryptoManager.encrypt(plaintext, null));
        assertArrayEquals(plaintext, cryptoManager.decrypt(encrypted));
    }

    @Test
    void providerCanHaveOnlyOneDecrypter() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> {
            DefaultCryptoManager.builder()
                .decrypter(provider.decrypter())
                .decrypter(provider.decrypter())
                .build();
        });
        assertTrue(e.getMessage().contains("Algorithm 'AEAD_AES_256_CBC_HMAC_SHA512' is already associated with decrypter com.couchbase.client.encryption.AeadAes256CbcHmacSha512Provider"));
    }


}

