package com.nullsploit.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.HandlerInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Set;
import java.util.Collections;
import java.util.HashSet;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    // Store globally valid session tokens
    public static final Set<String> activeTokens = Collections.synchronizedSet(new HashSet<>());

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new HandlerInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
                // Allow CORS preflights
                if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
                    return true;
                }

                String uri = request.getRequestURI();
                // Intercept all API calls except authentication endpoints
                if (uri.startsWith("/api/v2") && !uri.equals("/api/v2/auth")) {
                    String token = request.getHeader("X-Session-Token");
                    if (token == null) {
                        token = request.getParameter("token");
                    }
                    if (token == null || !activeTokens.contains(token)) {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.setContentType("application/json");
                        response.getWriter().write("{\"error\":\"unauthorized\",\"message\":\"Session token is missing or invalid\"}");
                        return false;
                    }
                }
                return true;
            }
        }).addPathPatterns("/api/v2/**");
    }
}
