package com.backend.globeonclick.configuration.jwt;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        // Permite el origen de tu frontend (local y en Railway)
        config.setAllowedOrigins(Arrays.asList(
                "http://localhost:5173", // Frontend local
                "https://pi-dh-infradeploytest-production.up.railway.app" // Frontend en Railway
        ));

        // Permite los métodos HTTP que necesitas
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"));

        // Permite todos los headers
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"));

        // Expone los headers que necesitas
        config.setExposedHeaders(List.of("Authorization"));

        // Permite credenciales
        config.setAllowCredentials(true);

        // Aplica la configuración a todas las rutas
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // No es necesario configurar CORS aquí si ya lo haces en corsFilter
            }
        };
    }
}