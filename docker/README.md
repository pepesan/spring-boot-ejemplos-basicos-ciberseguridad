# docker/

`compose.yaml` levanta dos herramientas de apoyo para practicar seguridad
sobre este repo:

```bash
cd docker
docker compose up -d
```

| Servicio    | Puerto | Notas |
|-------------|--------|-------|
| Juice Shop  | `3000` | Aplicación deliberadamente vulnerable de OWASP, para escanear/atacar con ZAP |
| SonarQube   | `9000` | Análisis estático de seguridad (SAST) sobre el código de este repo; login inicial `admin`/`admin` |

Los datos de SonarQube se guardan como bind-mounts en `docker/sonarqube-data`,
`docker/sonarqube-extensions` y `docker/sonarqube-logs` (ignorados por git),
en vez de volúmenes nombrados de Docker, para poder inspeccionarlos/borrarlos
directamente desde el propio checkout del repo.

Este mismo fichero es el que se incluye en `~/docker/compose.yaml` dentro de
la imagen Kasm `pepesan/mi-ubuntu-resolute-kasm-java-ciberseguridad-dind`; se
mantiene también aquí para poder levantar el entorno fuera de esa imagen,
clonando solo este repositorio.

## Analizar este proyecto con SonarQube

Con SonarQube ya arriba y un token generado (`My Account → Security →
Generate Token` en `http://localhost:9000`):

```bash
mvn org.sonarsource.scanner.maven:sonar-maven-plugin:5.1.0.4751:sonar \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=<tu-token>
```

Nota: el `pom.xml` de este repo aún no declara el `sonar-maven-plugin` ni
JaCoCo para cobertura, así que de momento hay que invocar el plugin
explícitamente como arriba en vez de con `mvn sonar:sonar`.
