package com.backend.globeonclick.services.implementation;

import io.mailtrap.client.MailtrapClient;
import io.mailtrap.config.MailtrapConfig;
import io.mailtrap.factory.MailtrapClientFactory;
import io.mailtrap.model.request.emails.Address;
import io.mailtrap.model.request.emails.MailtrapMail;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    @Value("${mailtrap.api.token}")
    private String mailtrapApiToken;

    private final String baseUrl = "https://pi-dh-infradeploytest-production.up.railway.app";
    private MailtrapClient mailtrapClient;

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

            initializeMailtrapClient();

            String emailHtml = buildEmailHtml(reservationId, userName, packageTitle,
                    adults, children, infants,
                    totalAmount, startDate, endDate);

            MailtrapMail mail = MailtrapMail.builder()
                    .from(new Address("noreply@demomailtrap.co", "GlobeOnClick"))
                    .to(List.of(new Address(userEmail)))
                    .subject("¡Gracias por tu reserva en Globe On Click!")
                    .html(emailHtml)
                    .category("Reserva Confirmación")
                    .build();

            var response = mailtrapClient.send(mail);
            log.debug("Respuesta de Mailtrap: {}", response);

            if (response.isSuccess()) {
                log.info("Correo enviado exitosamente a {}", userEmail);
                return true;
            } else {
                log.error("Error al enviar correo. Respuesta: {}", response.getErrors());
                return false;
            }
        } catch (Exception e) {
            log.error("Excepción al enviar correo: {}", e.getMessage(), e);
            return false;
        }
    }

    private void initializeMailtrapClient() {
        if (mailtrapClient == null) {
            MailtrapConfig config = new MailtrapConfig.Builder()
                    .token(mailtrapApiToken)
                    .build();
            mailtrapClient = MailtrapClientFactory.createMailtrapClient(config);
        }
    }

    private String buildEmailHtml(Long reservationId, String userName, String packageTitle,
                                  int adults, int children, int infants,
                                  double totalAmount, LocalDate startDate, LocalDate endDate) {
        // Mantener el mismo método de construcción de HTML que tenías antes
        return String.format("""
            [Tu HTML existente aquí...]
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