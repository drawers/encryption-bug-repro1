package com.gyaltsab.bugreproduce;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.test.runner.AndroidJUnit4;
import android.util.Base64;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertSame;
import static junit.framework.Assert.fail;

/**
 * Created by David on 10/06/2017.
 */
@RunWith(AndroidJUnit4.class)
public class CipherTest {

    private static final String ALGORITHM_RSA = "RSA";
    private static final String PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    KeyPair keyPair;

    @Before
    @TargetApi(Build.VERSION_CODES.M)
    public void setUp() throws Exception {
        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 20);

        int purposes = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("hello", purposes)
                .setKeySize(1024)
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateSubject(new X500Principal("CN=Cipher test"))
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime())
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build();

        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA, PROVIDER_ANDROID_KEY_STORE);
        generator.initialize(spec);
        keyPair = generator.generateKeyPair();
    }

    @Test
    @TargetApi(Build.VERSION_CODES.M)
    public void testDataSizeLessThan117_EncryptsAndDecryptsAsExpected() throws Exception {
        //arrange
        String plainText = stringOfLength(117);
        Cipher encryptCipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        String encrypted = null;

        //act
        byte[] plainData = plainText.getBytes("UTF-8");
        encrypted = encrypt(encryptCipher, plainData);
        Cipher decryptCipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());;
        String decrypted = decrypt(encrypted, decryptCipher);

        //assert
        assertEquals(plainText, decrypted);
    }

    @Test
    @TargetApi(Build.VERSION_CODES.M)
    public void testDataSize118_throwsRuntimeExceptionWithCorrectMessage() throws Exception {
        //arrange
        String plainText = stringOfLength(118);
        Cipher encryptCipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        //act
        byte[] plainData = plainText.getBytes("UTF-8");
        try {
            encrypt(encryptCipher, plainData);
            fail("Expected exception here");
        }

        //assert
        catch (Exception e) {
            assertSame(RuntimeException.class, e.getClass());
            assertEquals("error:0400006f:RSA routines:OPENSSL_internal:DATA_TOO_LARGE_FOR_KEY_SIZE", e.getMessage());
        }
    }

    @Test
    @TargetApi(Build.VERSION_CODES.M)
    public void testDataSize129_throwsRuntimeExceptionWithCorrectMessage() throws Exception {
        //arrange
        String plainText = stringOfLength(129);
        Cipher encryptCipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        //act
        byte[] plainData = plainText.getBytes("UTF-8");
        try {
            String encrypted = encrypt(encryptCipher, plainData);
            fail("Expected RuntimeException with DATA_TOO_LARGE_FOR_KEY_SIZE here but plaintext was encrypted to \""+ encrypted + "\" instead");
        }

        //assert
        catch (Exception e) {
            assertSame(RuntimeException.class, e.getClass());
            assertEquals("error:0400006f:RSA routines:OPENSSL_internal:DATA_TOO_LARGE_FOR_KEY_SIZE", e.getMessage());
        }
    }

    @NonNull
    private String decrypt(String encrypted, Cipher decryptCipher) throws IOException {
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(Base64.decode(encrypted.getBytes(), Base64.DEFAULT)), decryptCipher);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte)nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for(int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }

        return new String(bytes, 0, bytes.length, "UTF-8");
    }

    @NonNull
    private static String encrypt(Cipher cipher, byte[] plainText) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(baos, cipher);
        cipherOutputStream.write(plainText);
        cipherOutputStream.close();
        return Base64.encodeToString(baos.toByteArray(), Base64.DEFAULT);
    }

    private static String stringOfLength(int length) {
        return new String(new char[length]).replace("\0", "a");
    }
}
