package com.cursosdedesarrollo.ciberseguridad.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/redirect")
public class RedirectController {
    // 1. Muestra el formulario
    @GetMapping
    public String showForms() {
        return "redirect";
    }

    // 2. Vulnerable: redirige a cualquier URL
    @GetMapping("/vuln")
    public String vulnerable(@RequestParam String url) {
        // ¡Sin validación!
        return "redirect:" + url;
    }

    // 3. Seguro: sólo acepta rutas internas
    @GetMapping("/safe")
    public String safe(@RequestParam String url, Model model) {
        // Validar que url empiece por "/" (ruta interna)
        if (!url.startsWith("/")) {
            throw new IllegalArgumentException("URL no permitida para redirección");
        }
        return "redirect:/redirect" + url;
    }
    // 3. Seguro: sólo acepta rutas internas
    @GetMapping("/home")
    public String safeHome() {
        return "home";
    }
}
