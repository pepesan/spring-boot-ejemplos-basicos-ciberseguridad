package com.cursosdedesarrollo.ciberseguridad.controllers;

import com.cursosdedesarrollo.ciberseguridad.basic_auth.AuthUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Demostración educativa:
 * - /basic/secure -> HTTP Basic "casero"
 * - /digest/secure -> HTTP Digest MINIMAL (MD5, qop=auth)
 *
 * NO usar en producción.
 */
@RestController
public class BasicAndDigestController {

    // "Usuarios" en memoria solo para demo
    private static final Map<String, String> USERS = Map.of(
            "user", "password",
            "admin", "admin123"
    );

    private static final String REALM = "demo-realm";
    private static final String OPAQUE = "demo-opaque";
    private static final String QOP = "auth";
    private static final String ALGO = "MD5";

    /* ========================= BASIC ========================= */

    @GetMapping("/basic/secure")
    public ResponseEntity<String> basicSecure(@RequestHeader(value = "Authorization", required = false) String auth) {
        if (!StringUtils.hasText(auth) || !auth.startsWith("Basic ")) {
            return challengeBasic();
        }

        try {
            String b64 = auth.substring("Basic ".length()).trim();
            String decoded = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
            int idx = decoded.indexOf(':');
            if (idx < 0) return challengeBasic();

            String user = decoded.substring(0, idx);
            String pass = decoded.substring(idx + 1);
            String expected = USERS.get(user);
            if (expected != null && Objects.equals(expected, pass)) {
                return ResponseEntity.ok("OK BASIC, hola " + user);
            }
            return challengeBasic();
        } catch (Exception e) {
            return challengeBasic();
        }
    }

    private ResponseEntity<String> challengeBasic() {
        HttpHeaders h = new HttpHeaders();
        h.add("WWW-Authenticate", "Basic realm=\"" + REALM + "\"");
        return new ResponseEntity<>("Unauthorized (Basic)", h, HttpStatus.UNAUTHORIZED);
    }

    /* ========================= DIGEST ========================= */

    @GetMapping("/digest/secure")
    public ResponseEntity<String> digestSecure(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @RequestHeader(value = "X-HTTP-Method-Override", required = false) String methodOverride // por si prueban POST simulando
    ) {
        String method = "GET";
        if (StringUtils.hasText(methodOverride)) method = methodOverride;

        if (!StringUtils.hasText(auth) || !auth.startsWith("Digest ")) {
            return challengeDigest();
        }

        Map<String, String> params = parseDigestHeader(auth.substring("Digest ".length()));
        // Campos mínimos: username, realm, nonce, uri, response; opcionales: qop, nc, cnonce
        String username = params.get("username");
        String realm = params.get("realm");
        String nonce = params.get("nonce");
        String uri = params.get("uri");
        String response = params.get("response");
        String qop = params.getOrDefault("qop", "");
        String nc = params.getOrDefault("nc", "");
        String cnonce = params.getOrDefault("cnonce", "");

        if (!StringUtils.hasText(username) || !REALM.equals(realm) ||
                !StringUtils.hasText(nonce) || !StringUtils.hasText(uri) || !StringUtils.hasText(response)) {
            return challengeDigest();
        }
        if (!AuthUtils.validateNonce(nonce)) {
            return challengeDigest(); // nonce caducado/incorrecto -> nuevo reto
        }

        String password = USERS.get(username);
        if (password == null) return challengeDigest();

        // RFC "clásico" (MD5):
        // HA1 = MD5(username:realm:password)
        String ha1 = AuthUtils.md5Hex(username + ":" + REALM + ":" + password);
        // HA2 = MD5(method:uri)   (con qop=auth)
        String ha2 = AuthUtils.md5Hex(method + ":" + uri);

        final String expected;
        if ("auth".equalsIgnoreCase(qop)) {
            // response = MD5( HA1:nonce:nc:cnonce:qop:HA2 )
            expected = AuthUtils.md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);
        } else {
            // modo sin qop (no recomendado)
            expected = AuthUtils.md5Hex(ha1 + ":" + nonce + ":" + ha2);
        }

        if (expected.equalsIgnoreCase(response)) {
            return ResponseEntity.ok("OK DIGEST, hola " + username);
        }
        return challengeDigest();
    }

    private ResponseEntity<String> challengeDigest() {
        String nonce = AuthUtils.generateNonce();
        String header = String.format(
                "Digest realm=\"%s\", qop=\"%s\", nonce=\"%s\", opaque=\"%s\", algorithm=%s",
                REALM, QOP, nonce, OPAQUE, ALGO
        );
        HttpHeaders h = new HttpHeaders();
        h.add("WWW-Authenticate", header);
        return new ResponseEntity<>("Unauthorized (Digest)", h, HttpStatus.UNAUTHORIZED);
    }

    /** Parser simple para cabecera Digest key="value", key=value */
    private Map<String, String> parseDigestHeader(String s) {
        Map<String, String> map = new LinkedHashMap<>();
        // Split por comas que no estén dentro de comillas
        int i = 0;
        while (i < s.length()) {
            // saltar espacios y comas
            while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == ',')) i++;
            int eq = s.indexOf('=', i);
            if (eq < 0) break;
            String key = s.substring(i, eq).trim();
            i = eq + 1;
            String value;
            if (i < s.length() && s.charAt(i) == '\"') {
                i++;
                int end = i;
                StringBuilder sb = new StringBuilder();
                boolean escaped = false;
                while (end < s.length()) {
                    char c = s.charAt(end);
                    if (escaped) { sb.append(c); escaped = false; end++; continue; }
                    if (c == '\\') { escaped = true; end++; continue; }
                    if (c == '\"') { end++; break; }
                    sb.append(c); end++;
                }
                value = sb.toString();
                i = end;
            } else {
                int end = i;
                while (end < s.length() && s.charAt(end) != ',') end++;
                value = s.substring(i, end).trim();
                i = end;
            }
            map.put(key, value);
        }
        return map;
    }

    /* ========================= PUBLICO ========================= */

    @GetMapping("/publico/ping")
    public String publico() {
        return "OK público";
    }
}

