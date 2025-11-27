package com.cursosdedesarrollo.ciberseguridad.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.nio.file.*;

@Controller
@Slf4j
@RequestMapping("/files/read")
public class PathTransversalFileReadController {

    // Base seguro para el formulario “safe”
    private static final Path BASE_DIR = Paths.get("safeDir").toAbsolutePath().normalize();

    @GetMapping
    public String showForms() {
        return "fileReader";
    }

    @PostMapping("/vuln")
    public String readVulnerable(@RequestParam String directory,
                                 @RequestParam String filename,
                                 Model model) throws IOException {
        // Sin validación: concatenamos directo y leemos
        Path path = Paths.get(directory, filename);
        String content = Files.readString(path);
        model.addAttribute("content", content);
        return "fileReader";
    }

    @PostMapping("/safe")
    public String readSafe(@RequestParam String directory,
                           @RequestParam String filename,
                           Model model) throws IOException {
        // 1. Normalizar y comprobar que está bajo BASE_DIR
        Path target = Paths.get(directory, filename).toAbsolutePath().normalize();
        if (!target.startsWith(BASE_DIR)) {
            throw new IllegalArgumentException("Acceso a ruta no permitida");
        }
        // 2. Comprobar que no hay segmentos “..” en filename
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            throw new IllegalArgumentException("Nombre de fichero inválido");
        }
        log.info(target.toString());
        // 3. Leer el contenido
        String content = Files.readString(target);
        model.addAttribute("content", content);
        return "fileReader";
    }
}
