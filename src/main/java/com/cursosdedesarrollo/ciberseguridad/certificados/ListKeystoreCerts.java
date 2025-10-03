package com.cursosdedesarrollo.ciberseguridad.certificados;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class ListKeystoreCerts {
    public static void main(String[] args) throws Exception {
        // --- Configuración ---
        String keystorePath = "miKeystore.p12";        // keystore que ya teníamos
        String keystoreType = "PKCS12";                // tipo (PKCS12 o JKS)
        char[] keystorePass = "changeit".toCharArray(); // contraseña del keystore

        // 1) Cargar el keystore
        KeyStore ks = KeyStore.getInstance(keystoreType);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePass);
        }

        // 2) Enumerar alias
        Enumeration<String> aliases = ks.aliases();
        if (!aliases.hasMoreElements()) {
            System.out.println("No hay entradas en el keystore.");
        }

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias encontrado: " + alias);

            if (ks.isKeyEntry(alias)) {
                System.out.println(" - Tipo: Entrada de clave (private key + certificado).");

                Certificate[] chain = ks.getCertificateChain(alias);
                if (chain != null) {
                    for (int i = 0; i < chain.length; i++) {
                        System.out.println("   Certificado #" + (i+1) + ":");
                        printCertInfo((X509Certificate) chain[i]);
                    }
                }
            } else if (ks.isCertificateEntry(alias)) {
                System.out.println(" - Tipo: Certificado confiable (sin clave privada).");

                Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate x509) {
                    printCertInfo(x509);
                }
            }
            System.out.println("----------------------------------------------------");
        }
    }

    private static void printCertInfo(X509Certificate cert) {
        System.out.println("   Sujeto: " + cert.getSubjectDN());
        System.out.println("   Emisor : " + cert.getIssuerDN());
        System.out.println("   Válido desde: " + cert.getNotBefore());
        System.out.println("   Válido hasta: " + cert.getNotAfter());
        System.out.println("   Nº Serie: " + cert.getSerialNumber());
        System.out.println("   Algoritmo firma: " + cert.getSigAlgName());
    }
}

