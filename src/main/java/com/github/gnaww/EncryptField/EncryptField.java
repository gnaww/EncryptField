package com.github.gnaww.EncryptField;

import org.apache.kafka.common.cache.Cache;
import org.apache.kafka.common.cache.LRUCache;
import org.apache.kafka.common.cache.SynchronizedCache;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.connect.connector.ConnectRecord;
import org.apache.kafka.connect.data.Field;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.transforms.Transformation;
import org.apache.kafka.common.config.AbstractConfig;

import java.sql.*;
import java.util.*;

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public abstract class EncryptField<R extends ConnectRecord<R>> implements Transformation<R> {

    private final static String dbURL = "jdbc:postgresql://localhost:5432/enctest";
    private final static String dbUser = "wwang";
    private final static String dbPassword = "password";

    public static void generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey secretKey = keyGenerator.generateKey();
        String key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(key);

        try {
            Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            conn.setAutoCommit(false);
            System.out.println("Successfully connected to db, generating key");

            Statement stmt = conn.createStatement();
            String sql = "INSERT INTO enc_key (encryption_key) VALUES ('" + key + "');";
            stmt.executeUpdate(sql);

            stmt.close();
            conn.commit();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public record InitVector(int id, IvParameterSpec ivSpec) {}

    public static InitVector generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        int ivId = -1;

        try {
            Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            conn.setAutoCommit(false);
            System.out.println("Successfully connected to db, generating IV");

            String sql = "INSERT INTO init_vector (iv) VALUES (?);";
            PreparedStatement pst = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pst.setBytes(1, ivSpec.getIV());
            int affectedRows = pst.executeUpdate();

            if (affectedRows != 0) {
                ResultSet rs = pst.getGeneratedKeys();
                rs.next();
                ivId = rs.getInt(1);
            } else {
                System.out.println("error inserting generated IV into db");
            }

            pst.close();
            conn.commit();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return new InitVector(ivId, ivSpec);
    }

    private static SecretKey getEncryptionKey() {
        SecretKey key = null;
        try {
            Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            conn.setAutoCommit(false);
            System.out.println("Successfully connected to db, retrieving enc key");

            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM enc_key;");
            while (rs.next()) {
                int id = rs.getInt("id");
                String encryptionKey = rs.getString("encryption_key");
                byte[] encodedKey = Base64.getDecoder().decode(encryptionKey);
                key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
                // assume there is only one encryption key in the table
                break;
            }

            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return key;
    }

    public static String encrypt(String input, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey key = getEncryptionKey();
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey key = getEncryptionKey();
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static final String OVERVIEW_DOC = "Encrypt fields."
            + "<p/>Use the concrete transformation type designed for the record key (<code>" + Key.class.getName() + "</code>) "
            + "or value (<code>" + Value.class.getName() + "</code>).";

    interface ConfigName {
        String INCLUDE = "include";
    }

    public static final ConfigDef CONFIG_DEF = new ConfigDef()
            .define(ConfigName.INCLUDE, ConfigDef.Type.LIST, Collections.emptyList(), ConfigDef.Importance.MEDIUM,
                    "Fields to encrypt.");

    private List<String> include;

    private Cache<Schema, Schema> schemaUpdateCache;

    @Override
    public void configure(Map<String, ?> configs) {
        final SimpleConfig config = new SimpleConfig(CONFIG_DEF, configs);

        include = config.getList(ConfigName.INCLUDE);

        schemaUpdateCache = new SynchronizedCache<>(new LRUCache<>(16));
    }

    boolean filter(String fieldName) {
        return include.contains(fieldName);
    }

    @Override
    public R apply(R record) {
        if (operatingValue(record) == null) {
            return record;
        } else if (operatingSchema(record) == null) {
            return applySchemaless(record);
        } else {
            return applyWithSchema(record);
        }
    }

    private static IvParameterSpec getIvSpec(int ivId) {
        IvParameterSpec ivSpec = null;
        try {
            Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            conn.setAutoCommit(false);

            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM init_vector WHERE id = " + ivId + ";");
            rs.next();
            ivSpec = new IvParameterSpec(rs.getBytes("iv"));
            // assume there is only one encryption key in the table
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException err) {
            err.printStackTrace();
        }

        return ivSpec;
    }

    private R applySchemaless(R record) {
        final Map<String, Object> value = (Map<String, Object>) operatingValue(record);

        final Map<String, Object> updatedValue = new HashMap<>(value.size());

        for (Map.Entry<String, Object> e : value.entrySet()) {
            final String fieldName = e.getKey();
            if (e.getValue() == null) {
                updatedValue.put(fieldName, null);
            } else if (filter(fieldName)) {
                // get ivSpec from updatedValue (already generated one), or generate a new one and store it in updatedValue
                IvParameterSpec ivSpec;
                if (!updatedValue.containsKey("ivId")) {
                    InitVector iv = generateIv();
                    ivSpec = iv.ivSpec();
                    int ivId = iv.id();
                    updatedValue.put("ivId", ivId);
                } else {
                    ivSpec = getIvSpec((int) updatedValue.get("ivId"));
                }

                String encryptedFieldValue = "";
                try {
                    encryptedFieldValue = encrypt((String) e.getValue(), ivSpec);
                } catch (Exception err) {
                    err.printStackTrace();
                }
                updatedValue.put(fieldName, encryptedFieldValue);
            } else {
                updatedValue.put(fieldName, e.getValue());
            }
        }

        return newRecord(record, null, updatedValue);
    }

    private R applyWithSchema(R record) {
        final Struct value = (Struct) operatingValue(record);
        Schema updatedSchema = schemaUpdateCache.get(value.schema());
        if (updatedSchema == null) {
            updatedSchema = makeUpdatedSchema(value.schema());
            schemaUpdateCache.put(value.schema(), updatedSchema);
        }

        final Struct updatedValue = new Struct(updatedSchema);

        for (Field field : updatedSchema.fields()) {
            if (field.name().equals("ivId")) {
                continue;
            }
            Object fieldValue = value.get(field.name());
            if (fieldValue == null) {
                updatedValue.put(field.name(), null );
            } else if (filter(field.name())) {
                // get ivSpec from updatedValue (already generated one), or generate a new one and store it in updatedValue
                IvParameterSpec ivSpec = null;

                try {
                    int ivId = value.getInt32("ivId");
                    ivSpec = getIvSpec(ivId);
                } catch (Exception e) {
                    InitVector iv = generateIv();
                    ivSpec = iv.ivSpec();
                    int ivId = iv.id();
                    updatedValue.put("ivId", ivId);
                }

                String encryptedFieldValue = "";
                try {
                    encryptedFieldValue = encrypt((String) fieldValue, ivSpec);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                updatedValue.put(field.name(), encryptedFieldValue);
            } else {
                updatedValue.put(field.name(), fieldValue);
            }
        }

        return newRecord(record, updatedSchema, updatedValue);
    }

    private Schema makeUpdatedSchema(Schema schema) {
        final SchemaBuilder builder = SchemaUtil.copySchemaBasics(schema, SchemaBuilder.struct());
        for (Field field : schema.fields()) {
            builder.field(field.name(), field.schema());
        }
        builder.field("ivId", Schema.INT32_SCHEMA);
        return builder.build();
    }

    @Override
    public ConfigDef config() {
        return CONFIG_DEF;
    }

    @Override
    public void close() {
        schemaUpdateCache = null;
    }

    public static void main(String[] args) {
        System.out.println("hello i'm in main");
        try {
            EncryptField.generateKey(128);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    protected abstract Schema operatingSchema(R record);

    protected abstract Object operatingValue(R record);

    protected abstract R newRecord(R record, Schema updatedSchema, Object updatedValue);

    public static class Key<R extends ConnectRecord<R>> extends EncryptField<R> {

        @Override
        protected Schema operatingSchema(R record) {
            return record.keySchema();
        }

        @Override
        protected Object operatingValue(R record) {
            return record.key();
        }

        @Override
        protected R newRecord(R record, Schema updatedSchema, Object updatedValue) {
            return record.newRecord(record.topic(), record.kafkaPartition(), updatedSchema, updatedValue, record.valueSchema(), record.value(), record.timestamp());
        }

    }

    public static class Value<R extends ConnectRecord<R>> extends EncryptField<R> {

        @Override
        protected Schema operatingSchema(R record) {
            return record.valueSchema();
        }

        @Override
        protected Object operatingValue(R record) {
            return record.value();
        }

        @Override
        protected R newRecord(R record, Schema updatedSchema, Object updatedValue) {
            return record.newRecord(record.topic(), record.kafkaPartition(), record.keySchema(), record.key(), updatedSchema, updatedValue, record.timestamp());
        }

    }

    /**
     * A bare-bones concrete implementation of {@link AbstractConfig}.
     */
    private class SimpleConfig extends AbstractConfig {

        public SimpleConfig(ConfigDef configDef, Map<?, ?> originals) {
            super(configDef, originals, false);
        }

    }

    private static class SchemaUtil {

        public static SchemaBuilder copySchemaBasics(Schema source) {
            SchemaBuilder builder;
            if (source.type() == Schema.Type.ARRAY) {
                builder = SchemaBuilder.array(source.valueSchema());
            } else {
                builder = new SchemaBuilder(source.type());
            }
            return copySchemaBasics(source, builder);
        }

        public static SchemaBuilder copySchemaBasics(Schema source, SchemaBuilder builder) {
            builder.name(source.name());
            builder.version(source.version());
            builder.doc(source.doc());

            final Map<String, String> params = source.parameters();
            if (params != null) {
                builder.parameters(params);
            }

            return builder;
        }

    }
}
