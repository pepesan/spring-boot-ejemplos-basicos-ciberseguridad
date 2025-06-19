package com.cursosdedesarrollo.ciberseguridad.dtos;

import lombok.Data;

@Data
public class CookieDisplayDto {
    private String name;
    private String value;
    private String domain;
    private String path;
    private int maxAge;
    private boolean httpOnly;
    private boolean secure;
    // Note: SameSite is not directly a property of jakarta.servlet.http.Cookie,
    // it's an attribute added to the Set-Cookie header. We'll handle this
    // as a special case or omit for direct display for simplicity.
    // For this demo, let's add a placeholder string for SameSite.
    private String sameSiteStatus; // To describe SameSite behavior for the demo

    // Constructor to convert jakarta.servlet.http.Cookie to CookieDisplayDto
    public CookieDisplayDto(jakarta.servlet.http.Cookie cookie) {
        this.name = cookie.getName();
        this.value = cookie.getValue();
        this.domain = cookie.getDomain();
        this.path = cookie.getPath();
        this.maxAge = cookie.getMaxAge();
        this.httpOnly = cookie.isHttpOnly();
        this.secure = cookie.getSecure();
        // Default SameSite status for demonstration purposes.
        // Real SameSite value would require parsing the Set-Cookie header or Spring Security config.
        this.sameSiteStatus = "Lax (Default if not specified by browser)";
    }

    // Constructor for the SameSite=None cookie (as we set it manually via header)
    public CookieDisplayDto(String name, String value, String domain, String path, int maxAge, boolean httpOnly, boolean secure, String sameSiteStatus) {
        this.name = name;
        this.value = value;
        this.domain = domain;
        this.path = path;
        this.maxAge = maxAge;
        this.httpOnly = httpOnly;
        this.secure = secure;
        this.sameSiteStatus = sameSiteStatus;
    }


}
