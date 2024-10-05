package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;

public class CryptoExample {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String encrypt(String input, String algorithm, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encrypted, String algorithm, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(original);
    }

    public static void main(String[] args) {
        try {
            String text = "Hello, World!";
            String algorithmAES = "AES/ECB/PKCS5Padding";
            String algorithmTwofish = "Twofish/ECB/PKCS5Padding";

            // Chiave AES (16 byte per AES-128, 24 byte per AES-192, 32 byte per AES-256)
            byte[] keyAES = new byte[16];
            // Chiave Twofish (può essere di 16, 24 o 32 byte)
            byte[] keyTwofish = new byte[16];

            String encryptedAES = encrypt(text, algorithmAES, keyAES);
            String decryptedAES = decrypt(encryptedAES, algorithmAES, keyAES);

            String encryptedTwofish = encrypt(text, algorithmTwofish, keyTwofish);
            String decryptedTwofish = decrypt(encryptedTwofish, algorithmTwofish, keyTwofish);

            System.out.println("AES Encrypted: " + encryptedAES);
            System.out.println("AES Decrypted: " + decryptedAES);

            System.out.println("Twofish Encrypted: " + encryptedTwofish);
            System.out.println("Twofish Decrypted: " + decryptedTwofish);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

