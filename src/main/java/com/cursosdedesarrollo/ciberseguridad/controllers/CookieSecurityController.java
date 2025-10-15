package com.cursosdedesarrollo.ciberseguridad.controllers;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.cursosdedesarrollo.ciberseguridad.dtos.CookieDisplayDto;

@Controller
@RequestMapping("/cookies")
public class CookieSecurityController {
    @GetMapping
    public String showCookiePage(HttpServletRequest request, Model model) {
        List<CookieDisplayDto> displayCookies = new ArrayList<>();
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                // Check for the manually set SameSite=None cookie to provide correct status
                if ("sameSiteNoneCookie".equals(cookie.getName())) {
                    displayCookies.add(new CookieDisplayDto(
                            cookie.getName(),
                            cookie.getValue(),
                            cookie.getDomain(),
                            cookie.getPath(),
                            cookie.getMaxAge(),
                            cookie.isHttpOnly(),
                            cookie.getSecure(),
                            "None (Requiere Secure - para cross-site)"
                    ));
                } else {
                    displayCookies.add(new CookieDisplayDto(cookie));
                }
            }
        }
        model.addAttribute("existingCookies", displayCookies);
        return "cookies";
    }

    @GetMapping("/set")
    public String setCookies(HttpServletResponse response) {
        // 1. Cookie normal
        Cookie normalCookie = new Cookie("normalCookie", "valorNormal");
        normalCookie.setMaxAge(60 * 5);
        normalCookie.setPath("/");
        response.addCookie(normalCookie);

        // 2. Cookie HttpOnly
        Cookie httpOnlyCookie = new Cookie("httpOnlyCookie", "valorHttpOnly");
        httpOnlyCookie.setMaxAge(60 * 5);
        httpOnlyCookie.setPath("/");
        httpOnlyCookie.setHttpOnly(true);
        response.addCookie(httpOnlyCookie);

        // 3. Cookie Secure
        Cookie secureCookie = new Cookie("secureCookie", "valorSecure");
        secureCookie.setMaxAge(60 * 5);
        secureCookie.setPath("/");
        secureCookie.setSecure(true);
        response.addCookie(secureCookie);

        // 4. Cookie con SameSite=None (requiere Secure) - Añadido directamente al header
        Cookie sameSiteNoneSecureCookie = new Cookie("sameSiteNoneCookie", "valorSameSiteNone");
        sameSiteNoneSecureCookie.setMaxAge(60 * 5);
        sameSiteNoneSecureCookie.setPath("/");
        sameSiteNoneSecureCookie.setSecure(true);
        response.addHeader("Set-Cookie", sameSiteNoneSecureCookie.getName() + "=" + sameSiteNoneSecureCookie.getValue() +
                "; Max-Age=" + sameSiteNoneSecureCookie.getMaxAge() +
                "; Path=" + sameSiteNoneSecureCookie.getPath() +
                "; HttpOnly=" + sameSiteNoneSecureCookie.isHttpOnly() +
                "; Secure=" + sameSiteNoneSecureCookie.getSecure() +
                "; SameSite=Strict");

        return "redirect:/cookies";
    }

    @GetMapping("/clear")
    public String clearCookies(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                // Para eliminar una cookie, se establece su Max-Age a 0
                cookie.setMaxAge(0);
                cookie.setPath("/");
                // Important: If the original cookie had domain/secure/samesite,
                // these must be set on the deletion cookie to ensure it's found by the browser.
                // For simplicity in this demo, we assume default path and no domain for deletion.
                // For SameSite=None cookies, you might need to re-add the SameSite=None attribute for deletion to work.
                // For this demo, let's keep it simple for `clear`.
                if ("sameSiteNoneCookie".equals(cookie.getName())) {
                    response.addHeader("Set-Cookie", cookie.getName() + "=; Max-Age=0; Path=/; Secure; SameSite=None");
                } else {
                    response.addCookie(cookie);
                }
            }
        }
        return "redirect:/cookies";
    }
}
