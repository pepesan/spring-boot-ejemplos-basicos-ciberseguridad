package com.cursosdedesarrollo.ciberseguridad.controllers;

import org.owasp.encoder.Encode;
import lombok.extern.slf4j.Slf4j;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

@Controller
@RequestMapping("/xss")
@Slf4j
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
        // 3) Escape del payload para HTML
        String payloadLimpio= Encode.forHtml(payload);
        // 4) Si pasa, lo añadimos al modelo para renderizarlo escapado
        model.addAttribute("safePayload", payloadLimpio);
        // Alternativamente, podríamos usar Jsoup para sanitizar el input
        // Esto permite cierto HTML seguro, pero elimina scripts y atributos peligrosos
        String sanitizedComment = Jsoup.clean(payload, Safelist.basic());
        // Elimina cualquier etiqueta o atributo peligroso
        sanitizedComment = Jsoup.clean(payload, Safelist.none());
        log.info("Sanitized payload: {}", sanitizedComment);
        // 3) Si pasa, lo añadimos al modelo para renderizarlo escapado
        model.addAttribute("safePayload", sanitizedComment);
        return "xss";
    }
}
