package com.cursosdedesarrollo.ciberseguridad.controllers;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SqlInjectionController {
    // Endpoint formularios
    @GetMapping("/sqlinjection")
    public String sqlInjection() {
        return "sql_injection";
    }

    // Endpoint vulnerable: concatena directamente el parámetro
    @GetMapping("/sqlinjection/bad")
    public String sqlInjectionBad(
            @RequestParam(name = "input", required = false) String input,
            Model model) {

        if (input != null) {
            // Construcción insegura de la consulta
            String sqlBad = "SELECT * FROM users WHERE username = '" + input + "'";
            model.addAttribute("sqlBad", sqlBad);
            model.addAttribute("input", input);
        }
        return "sql_injection";
    }

    // Endpoint seguro: usa placeholder en la consulta (prepared statement)
    @GetMapping("/sqlinjection/good")
    public String sqlInjectionGood(
            @RequestParam(name = "input", required = false) String input,
            Model model) {

        if (input != null) {
            // Consulta parametrizada (mostramos solo la plantilla de la query)
            String sqlGood = "SELECT * FROM users WHERE username = ?";
            model.addAttribute("sqlGood", sqlGood);
            model.addAttribute("input", input);
        }
        return "sql_injection";
    }
}

