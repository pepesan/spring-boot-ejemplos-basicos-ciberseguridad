package com.cursosdedesarrollo.ciberseguridad.advices;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class XSSExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public String handleIllegalArgument(IllegalArgumentException ex, Model model) {
        // Añadimos el mensaje de error bajo el atributo "fallo"
        model.addAttribute("fallo", ex.getMessage());
        // Volvemos a la misma plantilla "xss" para mostrar el error
        return "fallo";
    }
}
