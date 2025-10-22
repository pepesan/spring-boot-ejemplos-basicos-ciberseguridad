# Aplicación: Spring Boot — Demo de vulnerabilidades web (puerto 8443)

## Resumen.
Esta aplicación Spring Boot es una demo educativa que intencionalmente expone endpoints con errores típicos de seguridad web (SQL Injection, CSRF, XSS, IDOR, file upload/reader inseguro, redirect abierto, SSRF, deserialización insegura, CORS mal configurado, cookies inseguras, inyección de comandos en SO). No la use en producción. Está pensada para aprendizaje, pruebas en entornos controlados y auditorías de seguridad local.

## Aviso legal y ético

Esta aplicación contiene vulnerabilidades a propósito. Sólo debe ejecutarse en entornos locales o entornos de laboratorio donde tengas permiso explícito para probar.

No te hagas responsable del uso indebido de este software. El autor no se hace responsable de actividades ilegales o daños causados por su uso.

## Requisitos

Java 17+ (o la versión que use tu proyecto Spring Boot)

Maven

## Instalación y ejecución
1. Construye el proyecto con Maven:
   ```bash
   mvn clean package
   ```
2. Ejecuta la aplicación:
```bash
   java -jar target/ciberseguridad-0.0.1-SNAPSHOT.jar
```
3. Accede a la aplicación en tu navegador web:
   ```
   https://localhost:8443
   ```
Es posible que debas aceptar un certificado autofirmado en tu navegador.



## Endpoints expuestos

La aplicación incluye (entre otros) los siguientes enlaces como elementos de navegación:

/sqlinjection — SQL Injection

/csrf — CSRF (Cross-Site Request Forgery)

/xss — XSS (Cross-Site Scripting)

/idor/1 — IDOR (Insecure Direct Object Reference) ejemplo con id 1

/idor/control/1 — IDOR Control (otro flujo para comparar)

/files — Upload (subida de archivos)

/files/read — File Reader (lectura de archivos del servidor)

/redirect — Redirect (open redirect)

/ssrf — SSRF (Server-Side Request Forgery)

/deserialization — Deserialization (deserialización insegura)

/cors — CORS (configuración débil)

/cookies — Cookies (flags de cookie inseguras, p. ej. sin HttpOnly/Secure)

/command-demo — SO Command injection (ejemplo de ejecución de comandos con entrada inadecuadamente saneada)

Estos endpoints están diseñados para mostrar la vulnerabilidad de manera clara. El comportamiento exacto (payloads aceptados, respuestas, parámetros) depende de la implementación del proyecto.

## HTTP AUTH BASIC
### Sin credenciales -> 401 + WWW-Authenticate: Basic realm="demo-realm"
curl -i https://localhost:8443/basic/secure

### Con credenciales correctas
curl -i -u user:password https://localhost:8443/basic/secure

## HTTP AUTH DIGEST
### Paso 1: obtén el reto -> 401 con WWW-Authenticate: Digest ...
curl -i https://localhost:8443/digest/secure

### Paso 2: usa curl con --digest (gestionará nonce/nc/cnonce automáticamente)
curl -i --digest -u user:password https://localhost:8443/digest/secure
