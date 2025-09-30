package com.cursosdedesarrollo.ciberseguridad.clonado;

import java.util.ArrayList;
import java.util.List;

// Clase que implementa clonación
class Usuario implements Cloneable {
    private String nombre;
    private List<String> roles;

    public Usuario(String nombre, List<String> roles) {
        this.nombre = nombre;
        this.roles = roles; // cuidado: referencia compartida
    }

    public String getNombre() {
        return nombre;
    }

    public List<String> getRoles() {
        return roles;
    }

    // Ejemplo de clonación insegura (shallow copy)
    @Override
    public Usuario clone() throws CloneNotSupportedException {
        return (Usuario) super.clone();
        // ¡OJO! la lista "roles" sigue apuntando al mismo objeto
    }

    // Versión segura de clonación (deep copy)
    public Usuario cloneSeguro() {
        List<String> copiaRoles = new ArrayList<>(this.roles);
        // Se crea una nueva lista, evitando referencias compartidas
        return new Usuario(this.nombre, copiaRoles);
    }
}
