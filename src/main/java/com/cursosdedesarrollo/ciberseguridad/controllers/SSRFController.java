package com.cursosdedesarrollo.ciberseguridad.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@Controller
@RequestMapping("/ssrf")
public class SSRFController {
    private final RestTemplate restTemplate = new RestTemplate();

    // 1. Formulario
    @GetMapping
    public String showForms() {
        return "ssrf";
    }

    // 2. Vulnerable: permite cualquier URL
    @PostMapping("/vuln")
    public String vulnerable(@RequestParam String url, Model model) {
        // ¡Sin validación!
        ResponseEntity<String> resp = restTemplate.getForEntity(url, String.class);
        model.addAttribute("result", resp.getBody());
        return "ssrf";
    }

    // 3. Seguro: sólo dominios confiables
    @PostMapping("/safe")
    public String safe(@RequestParam String url, Model model) {
        // 3.a Validar dominio
        if (!url.startsWith("https://jsonplaceholder.typicode.com/")) {
            throw new IllegalArgumentException("Host no permitido para la petición");
        }
        ResponseEntity<String> resp = restTemplate.getForEntity(url, String.class);
        model.addAttribute("result", resp.getBody());
        return "ssrf";
    }
}
