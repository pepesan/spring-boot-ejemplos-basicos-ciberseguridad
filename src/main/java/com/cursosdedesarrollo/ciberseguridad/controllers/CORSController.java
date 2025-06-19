package com.cursosdedesarrollo.ciberseguridad.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/cors")
@Slf4j
public class CORSController {
    // 1. Muestra la página de demo CORS
    @GetMapping
    public String showPage() {
        return "cors";
    }

    // 2. Endpoint vulnerable: permite cualquier origen
    @CrossOrigin(origins = "*")
    @GetMapping("/vuln/data")
    @ResponseBody
    public String getVulnerableData() {
        return "Datos públicos desde /cors/vuln/data";
    }

    // 3. Endpoint seguro: sólo permite un origen autorizado
    @CrossOrigin(origins = "http://localhost:8080")
    @GetMapping("/safe/data")
    @ResponseBody
    public String getSafeData(HttpServletRequest request ){
        String origin = request.getHeader("Origin");
        if (origin == null) {
            return "No se recibió header Origin";
        }
        return "Datos protegidos desde /cors/safe/data";
    }
}
