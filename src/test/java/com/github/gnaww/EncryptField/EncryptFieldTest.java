package com.github.gnaww.EncryptField;

import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.source.SourceRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptFieldTest {
    private EncryptField<SourceRecord> xform = new EncryptField.Value<>();
    private final static String dbURL = "jdbc:postgresql://localhost:5432/enctest";
    private final static String dbUser = "wwang";
    private final static String dbPassword = "password";

    @AfterEach
    public void teardown() {
        xform.close();
    }

    @Test
    public void tombstoneSchemaless() {
        final Map<String, String> props = new HashMap<>();
        props.put("include", "secret");

        xform.configure(props);

        final SourceRecord record = new SourceRecord(Collections.emptyMap(), Collections.emptyMap(), "test", null, null, null, null);
        final SourceRecord transformedRecord = xform.apply(record);

        assertNull(transformedRecord.value());
        assertNull(transformedRecord.valueSchema());
    }

    @Test
    public void tombstoneWithSchema() {
        final Map<String, String> props = new HashMap<>();
        props.put("include", "secret");

        xform.configure(props);

        final Schema schema = SchemaBuilder.struct()
                .field("customer", Schema.STRING_SCHEMA)
                .field("secret", Schema.STRING_SCHEMA)
                .build();

        final SourceRecord record = new SourceRecord(Collections.emptyMap(), Collections.emptyMap(), "test", null, null, schema, null);
        final SourceRecord transformedRecord = xform.apply(record);

        assertNull(transformedRecord.value());
        assertEquals(schema, transformedRecord.valueSchema());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void schemaless() {
        final Map<String, String> props = new HashMap<>();
        props.put("include", "secret");

        xform.configure(props);

        final Map<String, Object> value = new HashMap<>();
        value.put("customer", "hello1");
        value.put("secret", "world1");

        final SourceRecord record = new SourceRecord(Collections.emptyMap(), Collections.emptyMap(), "test", null, null, null, value);
        final SourceRecord transformedRecord = xform.apply(record);

        final Map<String, Object> updatedValue = (Map<String, Object>) transformedRecord.value();
        // expect customer name to be the same
        assertEquals("hello1", updatedValue.get("customer"));
        // expect customer secret to be encrypted from plaintext string
        assertNotEquals("world1", updatedValue.get("secret"));
        String decryptedSecret = "";
        try {
            Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            conn.setAutoCommit(false);

            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM init_vector WHERE id = " + updatedValue.get("ivId") + ";");
            rs.next();
            IvParameterSpec ivSpec = new IvParameterSpec(rs.getBytes("iv"));
            // assume there is only one encryption key in the table
            rs.close();
            stmt.close();
            conn.close();
            decryptedSecret = EncryptField.decrypt((String) updatedValue.get("secret"), ivSpec);
        } catch (Exception err) {
            err.printStackTrace();
        }
        assertEquals(decryptedSecret, "world1");
    }

    @Test
    public void withSchema() {
        final Map<String, String> props = new HashMap<>();
        props.put("include", "after, secret");

        xform.configure(props);

        final Schema nestedSchema = SchemaBuilder.struct()
                .field("test", Schema.STRING_SCHEMA)
                .field("id", Schema.INT32_SCHEMA)
                .build();

        final Schema schema = SchemaBuilder.struct()
                .field("customer", Schema.STRING_SCHEMA)
                .field("secret", Schema.STRING_SCHEMA)
                .field("after", nestedSchema)
                .build();

        final Struct nestedStruct = new Struct(nestedSchema);
        nestedStruct.put("test", "foobar");
        nestedStruct.put("id", 3);

        final Struct value = new Struct(schema);
        value.put("customer", "hello1");
        value.put("secret", "world1");
        value.put("after", nestedStruct);


        final SourceRecord record = new SourceRecord(Collections.emptyMap(), Collections.emptyMap(), "test", null, null, schema, value);
        final SourceRecord transformedRecord = xform.apply(record);

        final Struct updatedValue = (Struct) transformedRecord.value();
        System.out.println(updatedValue);

        // expect customer name to be the same
        assertEquals("hello1", updatedValue.getString("customer"));
        // expect customer secret to be encrypted from plaintext string
        assertNotEquals("world1", updatedValue.getString("secret"));
        String decryptedSecret = "";
        String decryptedNestedSecret = "";
        try {
            Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            conn.setAutoCommit(false);

            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM init_vector WHERE id = " + updatedValue.get("ivId") + ";");
            rs.next();
            IvParameterSpec ivSpec = new IvParameterSpec(rs.getBytes("iv"));
            // assume there is only one encryption key in the table
            rs.close();
            stmt.close();
            conn.close();
            decryptedSecret = EncryptField.decrypt(updatedValue.getString("secret"), ivSpec);
            Struct after = (Struct) updatedValue.get("after");
            decryptedNestedSecret = EncryptField.decrypt(after.getString("test"), ivSpec);
        } catch (Exception err) {
            err.printStackTrace();
        }
        assertEquals(decryptedSecret, "world1");
        assertEquals(decryptedNestedSecret, "foobar");
    }

//    public static void main(String[] args) {
//        System.out.println("hello i'm in main");
//        try {
//            com.github.gnaww.EncryptField.generateKey(128);
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//    }
}