package com.cursosdedesarrollo.ciberseguridad.certificados;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;

import org.bouncycastle.x509.X509V3CertificateGenerator;
import java.security.cert.X509Certificate;

public class KeystoreCreator {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Generar par de claves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Generar certificado autofirmado
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new org.bouncycastle.jce.X509Principal("CN=MiServidor"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)));
        certGen.setSubjectDN(new org.bouncycastle.jce.X509Principal("CN=MiServidor"));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        X509Certificate cert = certGen.generateX509Certificate(keyPair.getPrivate(), "BC");

        // Crear keystore y guardar clave + certificado
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("mialias", keyPair.getPrivate(), "changeit".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream("miKeystore.p12")) {
            ks.store(fos, "changeit".toCharArray());
        }

        System.out.println("Keystore creado con BouncyCastle: miKeystore.p12");
    }
}

