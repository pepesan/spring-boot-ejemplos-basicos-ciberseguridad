package com.cursosdedesarrollo.ciberseguridad.certificados;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CreateCer {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1) Par de claves para el sujeto
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        // 2) DN del sujeto/emisor (autofirmado)
        X500Name subject = new X500Name("CN=MiServidor, O=MiEmpresa, C=ES");

        // 3) Ventana de validez
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 24L * 3600 * 1000);         // desde ayer
        Date notAfter  = new Date(now + 365L * 24 * 3600 * 1000L); // +1 año

        // 4) Serial aleatorio
        BigInteger serial = new BigInteger(128, new SecureRandom());

        // 5) Builder X.509 v3
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, spki
        );

        // (Opcional) añadir extensiones útiles (KeyUsage, SAN, etc.)

        // 6) Firmar el cert
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));

        // 7) Guardarlo como DER .cer
        try (FileOutputStream fos = new FileOutputStream("certificado.cer")) {
            fos.write(cert.getEncoded());
        }
        System.out.println("Generado: certificado.cer (X.509 DER)");
    }
}

