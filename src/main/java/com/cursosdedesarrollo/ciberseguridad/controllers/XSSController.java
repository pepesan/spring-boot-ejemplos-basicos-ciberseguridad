package com.cursosdedesarrollo.ciberseguridad.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

@Controller
@RequestMapping("/xss")
public class XSSController {

    // 1. Mostrar el formulario inicial
    @GetMapping
    public String showForm() {
        return "xss";
    }

    // 2. Procesar el formulario vulnerable (sin escape)
    @PostMapping("/vulnerable")
    public String vulnerable(@RequestParam String payload, Model model) {
        // Añadimos el payload crudo al modelo
        model.addAttribute("vulnerablePayload", payload);
        return "xss";
    }

    // Patrón simple para detectar <script> o atributos onXXX
    private static final Pattern XSS_DETECT_PATTERN = Pattern.compile(
            "(<\\s*script)|"           // etiqueta <script
                    + "(on\\w+\\s*=)",            // atributos onload=, onclick=, onerror=, ...
            Pattern.CASE_INSENSITIVE
    );

    // 3. Procesar el formulario seguro (con escape automático)
    @PostMapping("/safe")
    public String safe(@RequestParam String payload, Model model) {
        // 1) Validación contra XSS
        Matcher m = XSS_DETECT_PATTERN.matcher(payload);
        if (m.find()) {
            // 2) Si coincide, lanzamos una excepción
            throw new IllegalArgumentException("Payload rechazado: contenido potencialmente peligroso");
        }
        // 3) Si pasa, lo añadimos al modelo para renderizarlo escapado
        model.addAttribute("safePayload", payload);
        return "xss";
    }
}
