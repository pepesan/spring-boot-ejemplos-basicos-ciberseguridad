package com.cursosdedesarrollo.ciberseguridad.clonado;

import java.util.ArrayList;
import java.util.List;

public class EjemploClonacion {
    public static void main(String[] args) throws CloneNotSupportedException {
        List<String> roles = new ArrayList<>();
        roles.add("USER");

        Usuario original = new Usuario("Ana", roles);

        // Clonación insegura
        Usuario clonInseguro = original.clone();
        clonInseguro.getRoles().add("ADMIN"); // modifica también al original

        System.out.println("Roles original (clon inseguro): " + original.getRoles());
        // Salida: [USER, ADMIN] -> riesgo: el clon alteró al original

        // Clonación segura
        Usuario clonSeguro = original.cloneSeguro();
        clonSeguro.getRoles().add("SUPERVISOR"); // solo afecta al clon

        System.out.println("Roles original (clon seguro): " + original.getRoles());
        // Salida: [USER, ADMIN] -> el original permanece intacto
        System.out.println("Roles clon seguro: " + clonSeguro.getRoles());
        // Salida: [USER, ADMIN, SUPERVISOR]
    }
}
