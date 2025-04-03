package com.backend.globeonclick.services.implementation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import lombok.RequiredArgsConstructor;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Arrays;

@Service
@RequiredArgsConstructor
public class EmailService {
    @Value("${mailtrap.api.token}")
    private String mailtrapApiToken;

    private final String baseUrl = "http://pi-dh-infradeploytest-production.up.railway.app";
    private final String MAILTRAP_API_URL = "https://send.api.mailtrap.io/api/send";
    private final RestTemplate restTemplate = new RestTemplate();

    public void sendConfirmationEmail(String userEmail, Long reservationId, String userName,
                                      String packageTitle, int adults, int children,
                                      int infants, double totalAmount,
                                      LocalDate startDate, LocalDate endDate) {
        try {
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
            headers.set("Api-Token", mailtrapApiToken);

            Map<String, Object> from = new HashMap<>();
            from.put("email", "hello@demomailtrap.co");
            from.put("name", "Globe On Click");

            Map<String, Object> to = new HashMap<>();
            to.put("email", userEmail);

            Map<String, Object> emailRequest = new HashMap<>();
            emailRequest.put("from", from);
            emailRequest.put("to", Arrays.asList(to));
            emailRequest.put("subject", "¡Gracias por tu reserva, Globe On!");
            emailRequest.put("html", emailHtml);
            emailRequest.put("category", "Reserva de Viaje");

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(emailRequest, headers);
            var response = restTemplate.postForEntity(MAILTRAP_API_URL, request, String.class);

            System.out.println("Email sent successfully to: " + userEmail);
            System.out.println("Mailtrap Response: " + response.getBody());
        } catch (Exception e) {
            System.err.println("Error sending email: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al enviar el email: " + e.getMessage());
        }
    }
}