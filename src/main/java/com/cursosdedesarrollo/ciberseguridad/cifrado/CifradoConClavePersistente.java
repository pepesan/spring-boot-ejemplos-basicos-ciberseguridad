package com.cursosdedesarrollo.ciberseguridad.cifrado;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.util.Base64;

public class CifradoConClavePersistente {
    private static final String CLAVE_PATH = "claveAES.key";

    public static void main(String[] args) throws Exception {
        // Generar o cargar clave
        SecretKey secretKey;
        if (new java.io.File(CLAVE_PATH).exists()) {
            secretKey = cargarClave();
            System.out.println("Clave cargada desde disco.");
        } else {
            secretKey = generarClave();
            guardarClave(secretKey);
            System.out.println("Clave generada y guardada en disco.");
        }

        // Texto a cifrar
        String textoOriginal = "Mensaje muy confidencial: 1234-5678-9999-0000";

        // Cifrar
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] textoCifrado = cipher.doFinal(textoOriginal.getBytes());
        String textoCifradoBase64 = Base64.getEncoder().encodeToString(textoCifrado);

        System.out.println("Texto cifrado: " + textoCifradoBase64);

        // Descifrar
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] textoDescifrado = cipher.doFinal(Base64.getDecoder().decode(textoCifradoBase64));
        System.out.println("Texto descifrado: " + new String(textoDescifrado));
    }

    // 🔑 Genera una clave AES de 128 bits
    private static SecretKey generarClave() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES-128
        return keyGen.generateKey();
    }

    // 💾 Guarda la clave en disco (formato binario RAW)
    private static void guardarClave(SecretKey secretKey) throws Exception {
        byte[] encoded = secretKey.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(CLAVE_PATH)) {
            fos.write(encoded);
        }
    }

    // 📂 Carga la clave desde disco
    private static SecretKey cargarClave() throws Exception {
        byte[] encoded;
        try (FileInputStream fis = new FileInputStream(CLAVE_PATH)) {
            encoded = fis.readAllBytes();
        }
        return new SecretKeySpec(encoded, "AES");
    }
}

