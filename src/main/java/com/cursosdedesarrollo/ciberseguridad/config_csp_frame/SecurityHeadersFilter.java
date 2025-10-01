package com.cursosdedesarrollo.ciberseguridad.config_csp_frame;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

// Un filtro simple que añade cabeceras para evitar el clickjacking
// y definir una política de seguridad de contenidos (CSP) para frames.
@Component
public class SecurityHeadersFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse r = (HttpServletResponse) res;
        r.setHeader("X-Frame-Options", "SAMEORIGIN");
        r.setHeader("Content-Security-Policy", "frame-ancestors 'self' https://partners.miempresa.com;");
        chain.doFilter(req, res);
    }
}

