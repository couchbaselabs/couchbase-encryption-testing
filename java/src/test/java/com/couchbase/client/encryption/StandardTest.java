/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.java.encryption.annotation.Encrypted;
import com.couchbase.client.java.json.JsonObject;
import com.couchbase.client.java.json.JsonObjectCrypto;
import com.couchbase.client.java.query.QueryResult;
import org.junit.jupiter.api.Test;

import static com.couchbase.client.java.query.QueryOptions.queryOptions;
import static org.junit.jupiter.api.Assertions.*;


public class StandardTest extends TestBase {
    public StandardTest() throws Exception {
        super();

    }

    @Test
    void basicFle() {
        Employee employee = new Employee();
        employee.setReplicant(true);
        collection.upsert("employeeId", employee); // encrypts the "replicant" field

        JsonObject encryptedJson = collection.get("employeeId")
            .contentAsObject()
            .getObject("encrypted$replicant");

        assertNotNull(encryptedJson);
        assertEquals(ALGORITHM, encryptedJson.get("alg"));
        assertEquals(KEY_ID, encryptedJson.get("kid"));
        assertNotNull(encryptedJson.get("ciphertext"));
    }

    @Test
    void basicDecryptedFle() {
        Employee employee = new Employee();
        employee.setReplicant(true);
        collection.upsert("employeeId", employee); // encrypts the "replicant" field

        Employee readItBack = collection.get("employeeId")
            .contentAs(Employee.class); // decrypts the "replicant" field
        assertTrue(readItBack.isReplicant());
    }

    @Test
    void partialEncryptedUpsertedDoc() {
        insertPartiallyEncryptedDoc("partialEncryptedDocId");
        JsonObject readItBack = collection.get("partialEncryptedDocId").contentAsObject();
        //unEncrypted can be accessed directly
        assertTrue(readItBack.getBoolean("unEncrypted"));

        assertNull(readItBack.getString("encryptedValue"));//Encrypted value cannot be accessed directly
        // checking it is in the expected encrypted format
        JsonObject mangledJson = readItBack.getObject("encrypted$encryptedValue");
        assertEquals(ALGORITHM, mangledJson.get("alg"));
        assertEquals(KEY_ID, mangledJson.get("kid"));
        assertNotNull(mangledJson.get("ciphertext"));
    }

    @Test
    void testDecryptionPartialFle() {
        insertPartiallyEncryptedDoc("partialEncryptedDocId");
        JsonObject readItBack = collection.get("partialEncryptedDocId").contentAsObject();
        JsonObjectCrypto readItBackCrypto = crypto.withObject(readItBack);
        assertEquals("This is encrypted Value", readItBackCrypto.getString("encryptedValue"));
        assertNull(readItBackCrypto.getObject("encrypted$encryptedValue"));
    }

    @Test
    void customFieldMangling() {
        enableCustomPrefix("customPrefix$");
        assertTrue(cryptoManager.isMangled("customPrefix$"));
        upsertDocument("testDocId", "encryptedFieldName", "encryptedFieldValue");
        validateCustomPrefix("customPrefix$", "testDocId", "encryptedFieldName");

        revertToDefaultPrefix();
        assertTrue(cryptoManager.isMangled("encrypted$"));
        upsertDocument("testDocId", "encryptedFieldName", "encryptedFieldValue");
        validateCustomPrefix("encrypted$", "testDocId", "encryptedFieldName");
    }

    @Test
    void partialEncryptionAllowsQueryUnEncrypted() {
        QueryResult result = cluster.query("select * from " + bucket.name() + "." + bucket.defaultCollection().scopeName() + "." + bucket.defaultCollection().name() + " where unEncrypted= $unEncrypted",
            queryOptions().parameters(JsonObject.create().put("unEncrypted", true))
        );

        assertNotEquals(0, result.rowsAsObject().size());
        assertTrue(result.rowsAsObject().get(0).getObject("_default").getBoolean("unEncrypted"));
        assertNull(result.rowsAsObject().get(0).getObject("_default").getObject("encryptedValue"));
        assertNotNull(result.rowsAsObject().get(0).getObject("_default").getObject("encrypted$encryptedValue"));
    }


    @Test
    void encryptedContentCannotBeQueried() {
        QueryResult result = cluster.query("select * from " + bucket.name() + "." + bucket.defaultCollection().scopeName() + "." + bucket.defaultCollection().name() + " where encryptedValue= $encryptedValue",
            queryOptions().parameters(JsonObject.create().put("encryptedValue", "This is encrypted Value"))
        );

        assertEquals(0, result.rowsAsObject().size());
    }
}


class Employee {
    @Encrypted
    private boolean replicant;

    // alternatively you could annotate the getter or setter
    public boolean isReplicant() {
        return replicant;
    }

    public void setReplicant(boolean replicant) {
        this.replicant = replicant;
    }
}
