package com.cursosdedesarrollo.ciberseguridad.certificados;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class ImportCerToKeystore {
    public static void main(String[] args) throws Exception {
        // --- Configuración ---
        String certDerPath   = "mialias.cer";   // certificado a importar (en DER)
        String keystorePath  = "miKeystore.p12";    // PKCS12 que ya creaste
        String keystoreType  = "PKCS12";            // Tipo correcto
        char[] keystorePass  = "changeit".toCharArray(); // Contraseña del keystore
        String alias         = "certexterno";       // Alias para el nuevo certificado

        // 1) Verificar que el fichero DER existe
        if (!Files.exists(Paths.get(certDerPath))) {
            throw new IllegalArgumentException("No existe el fichero: " + certDerPath);
        }

        // 2) Cargar certificado X.509 desde DER
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert;
        try (FileInputStream fis = new FileInputStream(certDerPath)) {
            cert = cf.generateCertificate(fis);
        }

        // 3) Abrir el keystore PKCS12 existente
        if (!Files.exists(Paths.get(keystorePath))) {
            throw new IllegalArgumentException("Keystore no encontrado: " + keystorePath);
        }
        KeyStore ks = KeyStore.getInstance(keystoreType);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePass);
        }

        // 4) (Opcional) comprobar si el alias ya existe
        if (ks.containsAlias(alias)) {
            System.out.println("Aviso: el alias '" + alias + "' ya existe. Se reemplazará.");
            ks.deleteEntry(alias);
        }

        // 5) Insertar el certificado en el PKCS12 como entrada confiable
        ks.setCertificateEntry(alias, cert);

        // 6) Guardar los cambios
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            ks.store(fos, keystorePass);
        }

        System.out.println("Certificado importado desde " + certDerPath +
                " en " + keystorePath + " como alias '" + alias + "'");
    }
}
