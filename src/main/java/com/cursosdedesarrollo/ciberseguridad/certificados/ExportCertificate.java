package com.cursosdedesarrollo.ciberseguridad.certificados;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class ExportCertificate {
    public static void main(String[] args) throws Exception {
        // Ruta y datos del keystore
        String keystorePath = "miKeystore.p12";
        String keystorePassword = "changeit";
        String alias = "mialias";

        // Cargar el keystore (tipo PKCS12)
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new java.io.FileInputStream(keystorePath), keystorePassword.toCharArray());

        // Obtener el certificado asociado al alias
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new RuntimeException("No se encontró el alias: " + alias);
        }

        // Guardar el certificado en formato X.509 (DER)
        try (FileOutputStream fos = new FileOutputStream(alias + ".cer")) {
            fos.write(cert.getEncoded());
        }

        // Imprimir algunos datos básicos del certificado
        if (cert instanceof X509Certificate x509) {
            System.out.println("Certificado exportado:");
            System.out.println("  Sujeto: " + x509.getSubjectDN());
            System.out.println("  Emisor: " + x509.getIssuerDN());
            System.out.println("  Válido desde: " + x509.getNotBefore());
            System.out.println("  Válido hasta: " + x509.getNotAfter());
        }

        System.out.println("Archivo creado: " + alias + ".cer");

        var base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(cert.getEncoded());

        try (var fos = new java.io.FileOutputStream(alias + ".pem")) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(base64.getBytes());
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
        }
        System.out.println("Exportado en PEM: " + alias + ".pem");

        java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
        if (chain != null && chain.length > 0) {
            try (var fos = new java.io.FileOutputStream(alias + "-fullchain.pem")) {
                var encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());
                for (var c : chain) {
                    fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
                    fos.write(encoder.encode(c.getEncoded()));
                    fos.write("\n-----END CERTIFICATE-----\n".getBytes());
                }
            }
            System.out.println("Cadena completa exportada: " + alias + "-fullchain.pem");
        }

        if (cert instanceof java.security.cert.X509Certificate x509) {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] fp = md.digest(x509.getEncoded());
            String hex = java.util.stream.IntStream.range(0, fp.length)
                    .mapToObj(i -> String.format("%02X", fp[i]))
                    .reduce((a,b) -> a + ":" + b).orElse("");
            System.out.println("Fingerprint SHA-256: " + hex);
        }


    }
}

