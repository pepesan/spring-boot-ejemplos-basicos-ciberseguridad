# Servidor HTTPS con Java con JSSE

## Creando el keystore

```bash
keytool -genkeypair \
  -alias localhost \
  -keyalg RSA -keysize 2048 -validity 365 \
  -storetype PKCS12 \
  -keystore httpsKeystore.p12 -storepass changeit \
  -dname "CN=localhost, OU=IT, O=MiEmpresa, L=Villares, ST=Salamanca, C=ES" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"
```
Coloca el fichero en el raiz del proyecto.

## Ejecuta el servidor HTTPS

Ejecuta la clase HttpsServerWithJSSE desde el propio IDE
