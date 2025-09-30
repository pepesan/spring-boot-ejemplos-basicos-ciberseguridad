package com.cursosdedesarrollo.ciberseguridad.record;

public class EjemploRecord {
    public static void main(String[] args) {
        // Crear una instancia del record
        Usuario u1 = new Usuario("Ana", "ana@mail.com", 30);

        // Acceder a los campos (no hay getters, se accede con el nombre del campo)
        System.out.println("Nombre: " + u1.nombre());
        System.out.println("Email: " + u1.email());
        System.out.println("Edad: " + u1.edad());

        // Comparación entre objetos (equals y hashCode vienen implementados automáticamente)
        Usuario u2 = new Usuario("Ana", "ana@mail.com", 30);
        System.out.println("¿Son iguales u1 y u2? " + u1.equals(u2)); // true

        // Representación en texto (toString también está generado automáticamente)
        System.out.println("Usuario: " + u1);

        // Intentar cambiar un campo -> NO es posible (inmutabilidad)
        // u1.nombre = "Pedro"; // ❌ error de compilación
    }
}
