package com.cursosdedesarrollo.ciberseguridad.controllers;

import lombok.extern.slf4j.Slf4j;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/html")
@Slf4j
public class HtmlInjectionController {

    /**
     * GET /html/form
     * Devuelve el formulario (html-form.html).
     */
    @GetMapping()
    public String form() {
        return "html-form";
    }

    /**
     * POST /html/submit
     * Procesa el comentario y prepara:
     *  - insecureResult: el texto recibido sin escape (demo con riesgo XSS).
     *  - secureResult: el mismo texto, pero mostrado de forma segura (escape).
     *
     * Parámetro opcional:
     *  - mode: "insecure" o "secure" (solo para indicar qué boton pulsó el usuario).
     * En este controlador devolvemos ambos resultados para comparar.
     */
    @PostMapping()
    public String submit(
            @RequestParam(name = "comment", required = false, defaultValue = "") String comment,
            @RequestParam(name = "mode", required = false, defaultValue = "insecure") String mode,
            Model model
    ) {
        // Raw input (siempre lo mostramos para evaluación didáctica)
        model.addAttribute("rawComment", comment);

        // INSEGURO: se mostrará tal cual (en la plantilla se usará th:utext)
        model.addAttribute("insecureResult", comment);

        // SEGURO: el mismo texto que se mostrará escapado (en la plantilla se usa th:text)
        model.addAttribute("secureResult", comment);

        // Información extra para la vista
        model.addAttribute("modeUsed", mode);
        model.addAttribute("note", "DEMO: El flujo INSEGURO usa th:utext y puede permitir XSS. No usar en producción.");

        return "html-result";
    }

    /**
     * Opcional: endpoint que muestra solo la versión segura (ejemplo didáctico).
     * GET /html/secure
     */
    @PostMapping("/secure")
    public String secureExample(Model model,
                                @RequestParam(name = "comment", required = false, defaultValue = "") String comment) {
        // Comprobamos que el comentario es seguro
        // Usando alguna biblioteca que valide o sanee el input
        // Sanitizamos el valor recibido para eliminar HTML potencialmente peligroso
        String sanitizedComment = Jsoup.clean(comment, Safelist.basic());
        log.info("Sanitized comment: {}", sanitizedComment);
        model.addAttribute("instruction", "Ejemplo de visualización segura (usa th:text).");
        // SEGURO: el mismo texto que se mostrará escapado (en la plantilla se usa th:text)
        model.addAttribute("safeComment", sanitizedComment);

        return "html-safe-result"; // si quieres una vista dedicada
    }
}
