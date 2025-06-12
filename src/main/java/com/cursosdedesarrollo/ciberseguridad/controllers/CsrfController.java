package com.cursosdedesarrollo.ciberseguridad.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.http.HttpServletRequest;

@Controller
public class CsrfController {

    // Carga la vista y añade CsrfToken solo para el formulario seguro
    @GetMapping("/csrf")
    public String showCsrfDemo(HttpServletRequest request, Model model) {
        String  token = "blablabla";
        model.addAttribute("safeCsrf", token);
        return "csrf_demo";
    }

    @PostMapping("/csrf/submit-safe")
    public String submitSafe(
            @RequestParam(name = "data", required = false) String data,
            @RequestParam(name = "csrf_token", required = false) String csrf_token,

            HttpServletRequest request,
            Model model) {
        if (csrf_token == null) {
            model.addAttribute("error", "Token invalido");
            return "fallo";
        }
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
}