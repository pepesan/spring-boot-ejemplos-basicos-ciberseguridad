package com.cursosdedesarrollo.ciberseguridad.cifrado;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmKeystoreDemo {

    // --- Configuración ---
    private static final String KEYSTORE_PATH = "secretos.p12";
    private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

    private static final String KEY_ALIAS = "aes-gcm-256";
    private static final char[] KEY_PASSWORD = "changeit".toCharArray(); // protección de la entrada

    // AES-GCM parámetros recomendados
    private static final int AES_KEY_BITS = 256;           // clave de 256 bits (recomendado)
    private static final int GCM_IV_BYTES = 12;            // 96 bits, recomendado por NIST
    private static final int GCM_TAG_BITS = 128;           // 128 bits de tag (recomendado)

    public static void main(String[] args) throws Exception {
        // 1) Obtener (o crear) la clave AES-GCM en un KeyStore PKCS#12
        SecretKey key = loadOrCreateAesKey();

        // 2) Texto a proteger
        String mensaje = "Mensaje muy confidencial: 1234-5678-9999-0000";

        // (Opcional) AAD para ligar el cifrado a un contexto (p. ej., ID de registro, versión, etc.)
        byte[] aad = "contexto-demo-v1".getBytes();

        // 3) Cifrar
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);
        byte[] ciphertext = encryptAesGcm(key, iv, aad, mensaje.getBytes());

        // Empaquetar: iv || ciphertext  (el tag va embebido en ciphertext por GCM)
        byte[] payload = concat(iv, ciphertext);
        String payloadB64 = Base64.getEncoder().encodeToString(payload);
        System.out.println("Payload (Base64, iv||ct): " + payloadB64);

        // 4) Descifrar
        byte[] payloadDecoded = Base64.getDecoder().decode(payloadB64);
        byte[] iv2 = slice(payloadDecoded, 0, GCM_IV_BYTES);
        byte[] ct2 = slice(payloadDecoded, GCM_IV_BYTES, payloadDecoded.length - GCM_IV_BYTES);

        byte[] plano = decryptAesGcm(key, iv2, aad, ct2);
        System.out.println("Texto descifrado: " + new String(plano));
    }

    // --- Cifrado / Descifrado AES-GCM ---

    private static byte[] encryptAesGcm(SecretKey key, byte[] iv, byte[] aad, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] decryptAesGcm(SecretKey key, byte[] iv, byte[] aad, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    // --- Gestión de KeyStore y clave ---

    private static SecretKey loadOrCreateAesKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        File f = new File(KEYSTORE_PATH);
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                ks.load(fis, KEYSTORE_PASSWORD);
            }
        } else {
            ks.load(null, null); // nuevo
        }

        // ¿Ya existe la entrada?
        if (ks.containsAlias(KEY_ALIAS)) {
            KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(KEY_PASSWORD);
            KeyStore.SecretKeyEntry ske = (KeyStore.SecretKeyEntry) ks.getEntry(KEY_ALIAS, prot);
            return ske.getSecretKey();
        }

        // Crear clave nueva AES-256
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS);
        SecretKey key = kg.generateKey();

        // Guardarla como entrada secreta en el PKCS#12
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(KEY_PASSWORD);
        ks.setEntry(KEY_ALIAS, entry, prot);

        try (FileOutputStream fos = new FileOutputStream(f)) {
            ks.store(fos, KEYSTORE_PASSWORD);
        }

        return key;
    }

    // --- Utilidades de bytes ---

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static byte[] slice(byte[] src, int off, int len) {
        byte[] r = new byte[len];
        System.arraycopy(src, off, r, 0, len);
        return r;
    }
}

