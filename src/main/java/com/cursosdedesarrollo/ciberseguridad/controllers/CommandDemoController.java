package com.cursosdedesarrollo.ciberseguridad.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;

@Controller
@RequestMapping("/command-demo")
public class CommandDemoController {

    // Lista blanca de comandos permitidos (ejemplo; adaptar al SO)
    private static final Map<String, List<String>> WHITELISTED_COMMANDS = Map.of(
            "fecha", List.of("date"),            // Linux/macOS
            "uptime", List.of("uptime"),
            "whoami", List.of("whoami")
    );

    @GetMapping
    public String form(Model model) {
        // Mensajes instructivos para la demo
        model.addAttribute("instructionInsecure", "Modo INSEGuro (SIMULADO): envía cualquier texto para ver cómo sería la ejecución sin controles (no se ejecuta).");
        model.addAttribute("instructionSecure", "Modo SEGURO: envía una de las claves permitidas: " + WHITELISTED_COMMANDS.keySet());
        return "command-demo";
    }

    @PostMapping
    public String handle(
            @RequestParam String input,
            @RequestParam(required = false, defaultValue = "insecure") String mode,
            Model model
    ) {
        // Mostramos la entrada recibida
        model.addAttribute("rawInput", input);

        // ---- Inseguro: SIMULACIÓN de ejecución sin controles (NO EJECUTA) ----
        String insecureExecResult = simulateInsecureExecution(input);
        model.addAttribute("insecureExecResult", insecureExecResult);

        // ---- Seguro: ejecución real, pero SOLO si está en la whitelist ----
        String secureResult;
        if ("secure".equals(mode)) {
            secureResult = handleSecureExecution(input);
        } else {
            secureResult = "No se ha solicitado ejecución segura.";
        }
        model.addAttribute("secureResult", secureResult);

        // Nota y timestamp
        model.addAttribute("note", "DEMO: el modo INSEGURO es una simulación. Nunca ejecute entrada arbitraria del usuario en producción.");
        model.addAttribute("ts", Instant.now().toString());

        return "command-demo";
    }

    /**
     * Simula la ejecución insegura: devuelve texto que muestra exactamente
     * qué se habría ejecutado y una salida simulada. NO ejecuta nada.
     */
    private String simulateInsecureExecution(String input) {
        if (input == null || input.isBlank()) {
            return "SIMULACIÓN: no se recibió entrada.";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("SIMULACIÓN DE EJECUCIÓN INSEGURA (NO EJECUTA)\n");
        sb.append("Comando recibido (sin controles):\n");
        sb.append(input).append("\n\n");
        sb.append("Resultado simulado:\n");
        sb.append(">> [Salida simulada] El comando habría sido pasado tal cual al shell.\n");
        sb.append(">> [Riesgo] Inyección posible: ejecución de pipes, redirecciones, etc.\n");
        return sb.toString();
    }

    /**
     * Manejo seguro real: si la entrada coincide con una clave de la whitelist,
     * se ejecuta el comando asociado usando ProcessBuilder con lista de argumentos.
     * Si no, se rechaza la ejecución.
     */
    private String handleSecureExecution(String input) {
        String key = input == null ? "" : input.trim().toLowerCase(Locale.ROOT);

        List<String> cmd = WHITELISTED_COMMANDS.get(key);
        if (cmd == null) {
            return "Comando no permitido o no reconocido. Comandos válidos: " + WHITELISTED_COMMANDS.keySet();
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Leer salida limitado
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                StringBuilder out = new StringBuilder();
                String line;
                int maxLines = 100;
                int lines = 0;
                while ((line = reader.readLine()) != null && lines++ < maxLines) {
                    out.append(line).append("\n");
                }
                // Intentamos esperar, pero con timeout práctico (simplificación)
                process.waitFor();
                return out.toString();
            }
        } catch (Exception e) {
            // No devolver detalles al usuario
            return "Error al ejecutar el comando seguro (ver logs para detalles).";
        }
    }
}