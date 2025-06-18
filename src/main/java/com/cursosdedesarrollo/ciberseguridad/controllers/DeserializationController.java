package com.cursosdedesarrollo.ciberseguridad.controllers;

import com.cursosdedesarrollo.ciberseguridad.dtos.Person;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;
import java.util.Objects;
import java.io.ObjectInputFilter.Status;

@Controller
@RequestMapping("/deserialization")
public class DeserializationController {
    @GetMapping
    public String showForm() {
        return "deserialization";
    }

    // 1. Vulnerable: deserializa sin filtros
    @PostMapping("/vuln")
    public String vulnerable(@RequestParam String data, Model model) throws Exception {
        // Limpio espacios y saltos de línea
        String clean = data.replaceAll("\\s+", "");

        byte[] bytes;
        try {
            // MimeDecoder ignora caracteres no Base64
            bytes = Base64.getMimeDecoder().decode(clean);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Payload Base64 inválido: " + ex.getMessage());
        }
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            Object obj = ois.readObject();  // ¡Aquí se ejecuta la deserialización insegura!
            model.addAttribute("result", Objects.toString(obj));
        }
        return "deserialization";
    }

    // 2. Seguro: sólo permite deserializar Person y clases java.*
    @PostMapping("/safe")
    public String safe(@RequestParam String data, Model model) throws Exception {
        String clean = data.replaceAll("\\s+", "");

        byte[] bytes;
        try {
            bytes = Base64.getMimeDecoder().decode(clean);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Payload Base64 inválido: " + ex.getMessage());
        }
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            // Definimos un filtro que sólo admite Person y clases del JDK
            ois.setObjectInputFilter(info -> {
                Class<?> cls = info.serialClass();
                if (cls == null) return Status.UNDECIDED;         // array, desc, etc.
                String name = cls.getName();
                if (name.equals("com.cursosdedesarrollo.ciberseguridad.dtos.Person")) return Status.ALLOWED;
                if (name.startsWith("java.")) return Status.ALLOWED;
                return Status.REJECTED;                           // cualquier otra clase
            });

            Object obj = ois.readObject();
            model.addAttribute("result", Objects.toString(obj));
        } catch (IllegalStateException ex) {
            // lanzada si el filtro rechaza la clase
            throw new IllegalArgumentException("Deserialización denegada: clase no permitida");
        }
        return "deserialization";
    }
    @GetMapping("/serial")
    @ResponseBody
    public String serial() throws Exception {
        Person p = new Person("Alice");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(p);
        }
        String base64 = Base64.getEncoder().encodeToString(bos.toByteArray());
        System.out.println(base64);
        return base64;
    }
}
