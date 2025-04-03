package com.backend.globeonclick.services.implementation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    @Value("${mailtrap.api.token}")
    private String mailtrapApiToken;

    private final String MAILTRAP_API_URL = "https://send.api.mailtrap.io/api/send";
    private final RestTemplate restTemplate = new RestTemplate();
    private final String baseUrl = "https://pi-dh-infradeploytest-production.up.railway.app";

    public boolean sendConfirmationEmail(String userEmail, Long reservationId, String userName,
                                         String packageTitle, int adults, int children,
                                         int infants, double totalAmount,
                                         LocalDate startDate, LocalDate endDate) {
        try {
            log.info("Iniciando envío de correo de confirmación para reserva #{} a {}", reservationId, userEmail);

            if (userEmail == null || userEmail.isBlank()) {
                log.error("Dirección de email no válida");
                return false;
            }

            String emailHtml = buildEmailHtml(reservationId, userName, packageTitle,
                    adults, children, infants,
                    totalAmount, startDate, endDate);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(mailtrapApiToken);

            var requestBody = Map.of(
                    "from", Map.of("email", "mailtrap@demomailtrap.com", "name", "GlobeOnClick"),
                    "to", List.of(Map.of("email", userEmail)),
                    "subject", "¡Gracias por tu reserva en Globe On Click!",
                    "html", emailHtml,
                    "category", "Reserva Confirmación"
            );

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody, headers);

            var response = restTemplate.postForEntity(MAILTRAP_API_URL, request, Map.class);

            log.debug("Respuesta de Mailtrap: {}", response.getBody());

            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("Correo enviado exitosamente a {}", userEmail);
                return true;
            } else {
                log.error("Error al enviar correo. Status: {}, Respuesta: {}",
                        response.getStatusCode(), response.getBody());
                return false;
            }
        } catch (Exception e) {
            log.error("Excepción al enviar correo: {}", e.getMessage(), e);
            return false;
        }
    }

    private String buildEmailHtml(Long reservationId, String userName, String packageTitle,
                                  int adults, int children, int infants,
                                  double totalAmount, LocalDate startDate, LocalDate endDate) {
        // Mantener el mismo método de construcción de HTML que tenías antes
        return String.format("""
            [Tu HTML existente...]
            """,
                userName,
                packageTitle,
                reservationId,
                startDate.format(DateTimeFormatter.ofPattern("d 'de' MMMM, yyyy", new Locale("es"))),
                endDate.format(DateTimeFormatter.ofPattern("d 'de' MMMM, yyyy", new Locale("es"))),
                adults,
                children,
                infants,
                totalAmount,
                baseUrl
        );
    }
}