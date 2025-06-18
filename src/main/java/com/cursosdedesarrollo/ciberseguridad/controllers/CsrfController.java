package com.cursosdedesarrollo.ciberseguridad.controllers;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Base64;

@Controller
public class CsrfController {

    // Carga la vista y añade CsrfToken solo para el formulario seguro
    @GetMapping("/csrf")
    public String showCsrfDemo(HttpSession session, Model model) {
        String  token = generarTokenUUID(128);
        // Almacena el valor bajo la clave "miClave"
        session.setAttribute("safeCsrf", token);
        model.addAttribute("safeCsrf", token);
        return "csrf_demo";
    }

    @PostMapping("/csrf/submit-safe")
    public String submitSafe(
            @RequestParam(name = "data", required = false) String data,
            @RequestParam(name = "csrf_token", required = false) String csrf_token,
            HttpSession session,
            HttpServletRequest request,
            Model model) {
        String token = (String) session.getAttribute("safeCsrf");
        if (csrf_token == null &&  csrf_token.equals(token)) {
            model.addAttribute("error", "Token invalido");
            return "fallo";
        }
        token = generarTokenUUID(128);
        // Almacena el valor bajo la clave "miClave"
        session.setAttribute("safeCsrf", token);
        model.addAttribute("safeCsrf", csrf_token);
        model.addAttribute("messageSafe", "Formulario seguro recibido: " + data);
        model.addAttribute("dataSafe", data);
        return "csrf_demo";
    }

    @PostMapping("/csrf/submit-unsafe")
    public String submitUnsafe(
            @RequestParam(name = "data", required = false) String data,
            Model model) {
        model.addAttribute("messageUnsafe", "Intento vulnerable con datos: " + data);
        model.addAttribute("dataUnsafe", data);
        return "csrf_demo";
    }

    public String generarTokenUUID(int numBytes) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[numBytes];
        secureRandom.nextBytes(bytes);
        // Codificamos en Base64 sin padding y apto para URLs
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}