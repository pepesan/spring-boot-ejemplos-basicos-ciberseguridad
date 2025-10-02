package com.cursosdedesarrollo.ciberseguridad.basic_auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

public class AuthUtils {
    private static final String NONCE_SECRET = "cambia-esta-clave-larga-y-aleatoria";
    private static final long NONCE_TTL_SECONDS = 300; // 5 minutos

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static String md5Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return toHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String base64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    public static String base64UrlNoPad(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static String signHmacSha256(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return base64UrlNoPad(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** nonce = base64url(timestamp:signature) */
    public static String generateNonce() {
        long ts = Instant.now().getEpochSecond();
        String payload = Long.toString(ts);
        String sig = signHmacSha256(payload, NONCE_SECRET);
        String token = payload + ":" + sig;
        return base64UrlNoPad(token.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean validateNonce(String nonceB64) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(nonceB64);
            String token = new String(decoded, StandardCharsets.UTF_8);
            String[] parts = token.split(":", 2);
            if (parts.length != 2) return false;
            long ts = Long.parseLong(parts[0]);
            String sig = parts[1];
            // check signature
            String expected = signHmacSha256(parts[0], NONCE_SECRET);
            if (!expected.equals(sig)) return false;
            // check age
            long age = Instant.now().getEpochSecond() - ts;
            return age >= 0 && age <= NONCE_TTL_SECONDS;
        } catch (Exception e) {
            return false;
        }
    }
}

