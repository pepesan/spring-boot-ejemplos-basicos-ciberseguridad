package com.cursosdedesarrollo.ciberseguridad.controllers;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/idor")
public class IDORController {


    // Mostrar perfil de usuario sin comprobar que sea el propio
    @GetMapping("/control/{id}")
    public String getControlUserProfile(@PathVariable Long id, Model model) {
        if (id == 1) {
            model.addAttribute("id", id);
            return "profile";
        }else {
            // 2) Si no coincide, lanzamos una excepción
            throw new IllegalArgumentException("ID rechazado: ID no válido");
        }

    }

    // Mostrar perfil de usuario sin comprobar que sea el propio
    @GetMapping("/{id}")
    public String getUserProfile(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "profile";
    }
}
