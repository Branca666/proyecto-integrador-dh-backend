package com.backend.globeonclick.services.implementation;

import com.backend.globeonclick.dto.request.ReservationRequestDTO;
import com.backend.globeonclick.dto.response.ReservationResponseDTO;
import com.backend.globeonclick.entity.Reservation;
import com.backend.globeonclick.entity.TourPackage;
import com.backend.globeonclick.entity.User;
import com.backend.globeonclick.exception.ResourceNotFoundException;
import com.backend.globeonclick.repository.IReservationRepository;
import com.backend.globeonclick.repository.ITourPackageRepository;
import com.backend.globeonclick.repository.IUserRepository;
import com.backend.globeonclick.services.interfaces.IReservationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ReservationService implements IReservationService {

    private final IReservationRepository reservationRepository;
    private final ITourPackageRepository tourPackageRepository;
    private final IUserRepository userRepository;
    private final EmailService emailService;

    @Override
    @Transactional
    public ReservationResponseDTO createReservation(ReservationRequestDTO requestDTO) {
        User user = userRepository.findById(requestDTO.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado"));
        
        TourPackage tourPackage = tourPackageRepository.findById(requestDTO.getPackageId())
                .orElseThrow(() -> new ResourceNotFoundException("Paquete turístico no encontrado"));

        // Verificar que el paquete tiene fechas válidas
        if (tourPackage.getStart_date() == null || tourPackage.getEnd_date() == null) {
            throw new IllegalStateException("El paquete turístico no tiene fechas válidas");
        }

        // Calcular monto total
        double basePrice = tourPackage.getPrice();
        double totalAmount = calculateTotalAmount(basePrice, requestDTO);

        Reservation reservation = Reservation.builder()
                .user(user)
                .tourPackage(tourPackage)
                .numberOfAdults(requestDTO.getNumberOfAdults())
                .numberOfChildren(requestDTO.getNumberOfChildren())
                .numberOfInfants(requestDTO.getNumberOfInfants())
                .totalAmount(totalAmount)
                .confirmationStatus("PENDING")
                .build();

        Reservation savedReservation = reservationRepository.save(reservation);
        ReservationResponseDTO responseDTO = mapToDTO(savedReservation);

        // Enviar correo de confirmación
        emailService.sendConfirmationEmail(
            user.getEmail(),
            savedReservation.getReservationId(),
            user.getName() + " " + user.getPaternalSurname(),
            tourPackage.getTitle(),
            savedReservation.getNumberOfAdults(),
            savedReservation.getNumberOfChildren(),
            savedReservation.getNumberOfInfants(),
            savedReservation.getTotalAmount(),
            tourPackage.getStart_date(),
            tourPackage.getEnd_date()
        );

        return responseDTO;
    }

    private double calculateTotalAmount(double basePrice, ReservationRequestDTO requestDTO) {
        // Adultos pagan precio completo
        double total = basePrice * requestDTO.getNumberOfAdults();
        
        // Niños pagan 50% del precio
        total += (basePrice * 0.5) * requestDTO.getNumberOfChildren();
        
        // Infantes no pagan
        // total += 0 * requestDTO.getNumberOfInfants();
        
        return total;
    }

    @Override
    @Transactional(readOnly = true)
    public List<ReservationResponseDTO> getAllReservations() {
        return reservationRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ReservationResponseDTO> getReservationById(Long id) {
        return reservationRepository.findById(id)
                .map(this::mapToDTO);
    }

    @Override
    @Transactional
    public ReservationResponseDTO updateReservation(Long id, ReservationRequestDTO requestDTO) {
        Reservation reservation = reservationRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Reservación no encontrada con ID: " + id));

        // Actualizar campos si se proporcionan en el DTO
        if (requestDTO.getUserId() != null) {
            User newUser = userRepository.findById(requestDTO.getUserId())
                    .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado con ID: " + requestDTO.getUserId()));
            reservation.setUser(newUser);
        }

        if (requestDTO.getPackageId() != null) {
            TourPackage newPackage = tourPackageRepository.findById(requestDTO.getPackageId())
                    .orElseThrow(() -> new ResourceNotFoundException("Paquete turístico no encontrado con ID: " + requestDTO.getPackageId()));
            reservation.setTourPackage(newPackage);
        }

        if (requestDTO.getConfirmationStatus() != null) {
            reservation.setConfirmationStatus(requestDTO.getConfirmationStatus());
        }

        if (requestDTO.getRating() != null) {
            reservation.setRating(requestDTO.getRating());
        }

        return mapToDTO(reservationRepository.save(reservation));
    }

    @Override
    @Transactional
    public void deleteReservation(Long id) {
        if (!reservationRepository.existsById(id)) {
            throw new ResourceNotFoundException("Reservación no encontrada con ID: " + id);
        }
        reservationRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ReservationResponseDTO> getReservationsByUserId(Long userId) {
        List<Reservation> reservations = reservationRepository.findByUserId(userId);
        return reservations.stream()
                .map(reservation -> {
                    System.out.println("Mapping reservation: " + reservation.getReservationId());
                    System.out.println("Tour package dates: " + 
                        "Start: " + reservation.getTourPackage().getStart_date() + 
                        ", End: " + reservation.getTourPackage().getEnd_date());
                    return mapToDTO(reservation);
                })
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public ReservationResponseDTO updateConfirmationStatus(Long id, String status) {
        Reservation reservation = reservationRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Reservación no encontrada con ID: " + id));
        
        reservation.setConfirmationStatus(status);
        return mapToDTO(reservationRepository.save(reservation));
    }

    @Override
    @Transactional
    public ReservationResponseDTO updateRating(Long id, String rating) {
        Reservation reservation = reservationRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Reservación no encontrada con ID: " + id));
        
        reservation.setRating(rating);
        return mapToDTO(reservationRepository.save(reservation));
    }

    @Override
    @Transactional
    public ReservationResponseDTO confirmReservationByEmail(Long id, String token) {
        Reservation reservation = reservationRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Reservación no encontrada con ID: " + id));

        // Aquí podrías validar el token si lo necesitas
        
        reservation.setConfirmationStatus("CONFIRMED");
        Reservation savedReservation = reservationRepository.save(reservation);
        
        return mapToDTO(savedReservation);
    }

    private ReservationResponseDTO mapToDTO(Reservation reservation) {
        TourPackage tourPackage = reservation.getTourPackage();
        System.out.println("Mapping dates for reservation " + reservation.getReservationId() + 
                          ": Start=" + tourPackage.getStart_date() + 
                          ", End=" + tourPackage.getEnd_date());
                          
        return ReservationResponseDTO.builder()
                .reservationId(reservation.getReservationId())
                .userId(reservation.getUser().getUserId())
                .userName(reservation.getUser().getName() + " " + reservation.getUser().getPaternalSurname())
                .packageId(tourPackage.getPackageId())
                .packageTitle(tourPackage.getTitle())
                .numberOfAdults(reservation.getNumberOfAdults())
                .numberOfChildren(reservation.getNumberOfChildren())
                .numberOfInfants(reservation.getNumberOfInfants())
                .totalAmount(reservation.getTotalAmount())
                .confirmationStatus(reservation.getConfirmationStatus())
                .rating(reservation.getRating())
                .startDate(tourPackage.getStart_date())
                .endDate(tourPackage.getEnd_date())
                .build();
    }
} 