package com.cursosdedesarrollo.ciberseguridad.controllers;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.*;
import java.util.Arrays;
import java.util.List;

@Controller
@RequestMapping("/files")
public class FileUploadController {

    private static final String UPLOAD_DIR = "/tmp";

    // 1. Mostrar formulario de subida
    @GetMapping("")
    public String showUploadForm() {
        return "uploadForm";
    }

    // Tamaño máximo en bytes (por ejemplo, 5 MB)
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024L;

    // Extensiones permitidas (sin punto)
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("png", "jpg", "jpeg", "txt", "pdf");

    // MIME types permitidos
    private static final List<String> ALLOWED_MIME_TYPES = Arrays.asList(
            "image/png", "image/jpeg", "text/plain", "application/pdf"
    );

    // 2. Procesar subida
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file, Model model) {
        // 1. Si no hay fichero, error
        if (file.isEmpty()) {
            throw new IllegalArgumentException("No se ha seleccionado ningún fichero para subir.");
        }

        // 2. Comprueba tamaño
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("El fichero excede el tamaño máximo permitido de 5 MB.");
        }

        // 3. Comprueba MIME type
        String mimeType = file.getContentType();
        if (mimeType == null || !ALLOWED_MIME_TYPES.contains(mimeType)) {
            throw new IllegalArgumentException("Tipo MIME no permitido: " + mimeType);
        }

        // 4. Comprueba extensión
        String filename = file.getOriginalFilename();
        if (filename == null || !filename.contains(".")) {
            throw new IllegalArgumentException("Nombre de fichero inválido.");
        }
        String ext = filename.substring(filename.lastIndexOf('.') + 1).toLowerCase();
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new IllegalArgumentException("Extensión no permitida: ." + ext);
        }

        // 5. Intentar guardar el fichero
        try {
            Path uploadPath = Paths.get(UPLOAD_DIR);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }
            Path target = uploadPath.resolve(file.getOriginalFilename());
            file.transferTo(target.toFile());
        } catch (IOException e) {
            // Si falla el guardado, propagamos un RuntimeException
            throw new RuntimeException("Error al guardar el fichero.", e);
        }

        // 6. Éxito: añadimos atributo para la vista
        model.addAttribute("success", "Fichero subido con éxito: " + file.getOriginalFilename());
        return "uploadForm";
    }
}
