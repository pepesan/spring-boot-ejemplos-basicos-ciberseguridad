package com.cursosdedesarrollo.ciberseguridad.servidor_https;

import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.Executors;

public class HttpsServerWithJSSE {

    // --- Configuración ---
    private static final String HOST = "localhost";
    private static final int PORT = 8443;

    // Keystore del servidor (identidad)
    private static final String KEYSTORE_PATH = "httpsKeystore.p12";
    private static final char[] KEYSTORE_PASS = "changeit".toCharArray();
    private static final char[] KEY_PASS = "changeit".toCharArray(); // misma que el keystore si no cambiaste

    // Truststore (solo si quieres mTLS). De lo contrario, déjalo en null y needClientAuth=false.
    private static final String TRUSTSTORE_PATH = null; // p.ej. "miTruststore.p12"
    private static final char[] TRUSTSTORE_PASS = "changeit".toCharArray();

    // ¿Exigir certificado de cliente?
    private static final boolean REQUIRE_MTLS = false;

    public static void main(String[] args) throws Exception {
        SSLContext sslContext = buildSSLContext();

        HttpsServer server = HttpsServer.create(new InetSocketAddress(HOST, PORT), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    SSLContext c = getSSLContext();
                    SSLEngine engine = c.createSSLEngine();
                    engine.setUseClientMode(false);

                    // Protocolos preferidos (orden de preferencia)
                    List<String> desiredProtocols = List.of("TLSv1.3", "TLSv1.2");
                    String[] protocols = intersectOrdered(desiredProtocols, engine.getSupportedProtocols());

                    // Cifrados preferidos (TLS 1.3 + buenos de 1.2 como fallback)
                    List<String> desiredCiphers = List.of(
                            "TLS_AES_256_GCM_SHA384",
                            "TLS_AES_128_GCM_SHA256",
                            "TLS_CHACHA20_POLY1305_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    );
                    String[] ciphers = intersectOrdered(desiredCiphers, engine.getSupportedCipherSuites());

                    SSLParameters sp = c.getDefaultSSLParameters();
                    if (protocols.length > 0) sp.setProtocols(protocols);
                    if (ciphers.length > 0) sp.setCipherSuites(ciphers);

                    params.setSSLParameters(sp);
                    params.setNeedClientAuth(REQUIRE_MTLS);
                } catch (Exception e) {
                    throw new RuntimeException("Fallo configurando HTTPS", e);
                }
            }
        });

        // Contexto simple GET /hello
        server.createContext("/hello", exchange -> {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String body = "Hola desde HTTPS con JSSE 👋";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.out.printf("✅ Servidor HTTPS arriba: https://%s:%d/hello%n", HOST, PORT);
        if (REQUIRE_MTLS) System.out.println("🔒 mTLS ACTIVADO (client cert requerido)");
    }

    private static SSLContext buildSSLContext()
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException, KeyManagementException {

        // Keystore con clave privada + cert del servidor
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            ks.load(fis, KEYSTORE_PASS);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, KEY_PASS);

        TrustManagerFactory tmf = null;
        if (TRUSTSTORE_PATH != null) {
            KeyStore ts = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
                ts.load(fis, TRUSTSTORE_PASS);
            }
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
        } else {
            // Si no pasas truststore, usará el de la JVM para validar clientes (si mTLS)
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
        }

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return ctx;
    }

    private static String[] intersectOrdered(List<String> desired, String[] supported) {
        Set<String> sup = new HashSet<>(Arrays.asList(supported));
        return desired.stream().filter(sup::contains).toArray(String[]::new);
    }
}

