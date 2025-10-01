package com.cursosdedesarrollo.ciberseguridad.controllers;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.*;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.util.regex.Pattern;

@Controller
@RequestMapping("/xpath-demo")
public class XPathDemoController {

    // Patrón de whitelist ejemplo: solo letras, números y espacios (ajustar según necesidad)
    private static final Pattern VALID_NAME = Pattern.compile("^[A-Za-z0-9\\s]{1,64}$");

    @GetMapping
    public String form(Model model) {
        model.addAttribute("instructionInsecure", "Modo INSEGURO: se construye la consulta XPath concatenando la entrada. (Demo sólo en entorno seguro)");
        model.addAttribute("instructionSecure", "Modo SEGURO: validación por whitelist y construcción de literal XPath seguro.");
        return "xpath-demo";
    }

    @PostMapping
    public String handle(
            @RequestParam String input,
            @RequestParam(required = false, defaultValue = "insecure") String mode,
            Model model
    ) {
        model.addAttribute("rawInput", input);

        // Cargar Document XML de forma segura (prevención XXE)
        Document doc;
        try {
            doc = loadXmlDocumentSecure("users.xml");
        } catch (Exception e) {
            model.addAttribute("error", "Error cargando XML de ejemplo (ver logs).");
            return "xpath-demo";
        }

        // ---- INSEGURO: construcción por concatenación (demostración educativa) ----
        String insecureResult;
        try {
            String expr = "/users/user[name/text()='" + input + "']/email/text()";
            insecureResult = evaluateXPath(doc, expr);
        } catch (Exception e) {
            insecureResult = "ERROR (inseguro): " + e.getMessage();
        }
        model.addAttribute("insecureResult", insecureResult);

        // ---- SEGURO: validación y literal XPath seguro ----
        String secureResult;
        try {
            if (!isValidName(input)) {
                secureResult = "Entrada rechazada por validación (no cumple whitelist).";
            } else {
                String literal = toXPathStringLiteral(input);
                String exprSafe = "/users/user[name/text()=" + literal + "]/email/text()";
                secureResult = evaluateXPath(doc, exprSafe);
            }
        } catch (Exception e) {
            secureResult = "ERROR (seguro): " + e.getMessage();
        }
        model.addAttribute("secureResult", secureResult);

        return "xpath-demo";
    }

    // Carga segura de XML: configura el parser para evitar XXE y entidades externas
    private Document loadXmlDocumentSecure(String classpathResource) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // Características de seguridad
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // Desactivar DOCTYPE
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // Desactivar inclusión externa y expansión de entidades
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);

        DocumentBuilder db = dbf.newDocumentBuilder();

        ClassPathResource res = new ClassPathResource(classpathResource);
        try (InputStream is = res.getInputStream()) {
            return db.parse(is);
        }
    }

    // Evalúa una expresión XPath y devuelve el resultado como String (primer match o vacío)
    private String evaluateXPath(Document doc, String expression) throws XPathExpressionException {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        XPathExpression xpe = xpath.compile(expression);
        String result = (String) xpe.evaluate(doc, XPathConstants.STRING);
        if (result == null) result = "";
        return result.trim();
    }

    // Whitelist simple
    private boolean isValidName(String input) {
        if (input == null) return false;
        return VALID_NAME.matcher(input).matches();
    }

    /**
     * Construye un literal XPath seguro para un string Java.
     * - Si no contiene comillas simples, devuelve 'value'
     * - Si contiene comillas simples, usa concat(...) para evitar romper la literal
     */
    private String toXPathStringLiteral(String value) {
        if (value == null) return "''";
        if (!value.contains("'")) {
            return "'" + value + "'";
        }
        String[] parts = value.split("'");
        StringBuilder sb = new StringBuilder("concat(");
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                sb.append(", \"'\", ");
            }
            sb.append("'").append(parts[i]).append("'");
        }
        sb.append(")");
        return sb.toString();
    }
}

