package com.cursosdedesarrollo.ciberseguridad.cifrado;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class CifradoDescifradoAES {
    public static void main(String[] args) throws Exception {
        // 1. Generar una clave simétrica AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // también se puede 192 o 256 (si lo soporta el JCE)
        SecretKey secretKey = keyGen.generateKey();

        // 2. Texto que queremos proteger
        String textoOriginal = "Mensaje muy confidencial: 1234-5678-9999-0000";

        // 3. Configurar el Cipher para ENCRIPTAR
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] textoCifrado = cipher.doFinal(textoOriginal.getBytes());

        // Codificar en Base64 para mostrarlo como texto
        String textoCifradoBase64 = Base64.getEncoder().encodeToString(textoCifrado);
        System.out.println("Texto cifrado: " + textoCifradoBase64);

        // 4. Configurar el Cipher para DESENCRIPTAR
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] textoDescifrado = cipher.doFinal(Base64.getDecoder().decode(textoCifradoBase64));

        System.out.println("Texto descifrado: " + new String(textoDescifrado));
    }
}

