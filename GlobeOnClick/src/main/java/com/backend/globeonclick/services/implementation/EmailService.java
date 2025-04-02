package com.backend.globeonclick.services.implementation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {
    @Value("${resend.api.key}")
    private String resendApiKey;

    private final String baseUrl = "https://pi-dh-infradeploytest-production.up.railway.app";
    private final String RESEND_API_URL = "https://api.resend.com/emails";
    private final RestTemplate restTemplate = new RestTemplate();

    public boolean sendConfirmationEmail(String userEmail, Long reservationId, String userName,
                                         String packageTitle, int adults, int children,
                                         int infants, double totalAmount,
                                         LocalDate startDate, LocalDate endDate) {
        try {
            log.info("Iniciando envío de correo de confirmación para reserva #{} a {}", reservationId, userEmail);

            String emailHtml = String.format("""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; padding: 20px;">
                        <h1 style="color: #0b2f53; margin: 0;">¡Gracias por tu reserva, Globe On Click!</h1>
                    </div>
                    
                    <div style="border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
                        <p style="font-size: 16px; margin: 10px 0;">Has reservado el paquete: <strong>%s</strong></p>
                        <p style="font-size: 16px; margin: 10px 0;">Tu número de reserva es: <strong>#%d</strong></p>
                        
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="color: #0b2f53; margin-top: 0;">Fechas del viaje:</h3>
                            <p style="margin: 5px 0;">Salida: <strong>%s</strong></p>
                            <p style="margin: 5px 0;">Regreso: <strong>%s</strong></p>
                        </div>

                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="color: #0b2f53; margin-top: 0;">Detalles de huéspedes:</h3>
                            <ul style="list-style: none; padding: 0; margin: 0;">
                                <li>• %d Adultos</li>
                                <li>• %d Niños</li>
                                <li>• %d Infantes</li>
                            </ul>
                        </div>

                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="color: #0b2f53; margin-top: 0;">Monto total: <strong>$%.2f</strong></h3>
                        </div>
                        
                        <p style="font-size: 16px; margin: 10px 0;">Estado: <span style="color: #ffa500;">Pendiente de confirmación</span></p>
                        
                        <div style="text-align: center; margin-top: 30px;">
                            <a href="%s/mis-reservaciones" 
                               style="background-color: #0b2f53; 
                                      color: white; 
                                      padding: 12px 25px; 
                                      text-decoration: none; 
                                      border-radius: 5px; 
                                      display: inline-block;">
                                Ver mi reserva
                            </a>
                        </div>
                    </div>
                </div>
                """,
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

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(resendApiKey);

            var emailRequest = new EmailRequest(
                    "GlobeOnClick <onboarding@resend.dev>",
                    userEmail,
                    "¡Gracias por tu reserva, Globe On!",
                    emailHtml
            );

            HttpEntity<EmailRequest> request = new HttpEntity<>(emailRequest, headers);
            var response = restTemplate.postForEntity(RESEND_API_URL, request, String.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                log.info("Correo enviado exitosamente a: {}", userEmail);
                return true;
            } else {
                log.error("Error al enviar correo. Código de estado: {}", response.getStatusCode());
                return false;
            }
        } catch (Exception e) {
            log.error("Error al enviar correo de confirmación: {}", e.getMessage(), e);
            return false;
        }
    }

    private record EmailRequest(
            String from,
            String to,
            String subject,
            String html
    ) {}
}