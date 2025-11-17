package com.cursosdedesarrollo.ciberseguridad.controllers;

import com.cursosdedesarrollo.ciberseguridad.dtos.PersonDTO;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/valid")
public class ValidController {

    @PostMapping("")
    public String getUserProfile(@Valid @RequestBody PersonDTO personDTO) {
        return "Hello, " + personDTO.getName();
    }
}
