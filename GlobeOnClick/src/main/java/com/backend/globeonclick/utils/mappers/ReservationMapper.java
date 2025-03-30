package com.backend.globeonclick.utils.mappers;

import com.backend.globeonclick.dto.request.ReservationRequestDTO;
import com.backend.globeonclick.dto.response.ReservationResponseDTO;
import com.backend.globeonclick.dto.response.TourPackageResponseDTO;
import com.backend.globeonclick.entity.Reservation;
import org.springframework.stereotype.Component;

@Component
public class ReservationMapper {
    public ReservationResponseDTO toResponseDTO(Reservation reservation) {
        if (reservation == null) return null;
        
        System.out.println("Mapping reservation: " + reservation.getReservationId());
        System.out.println("Tour package dates: " + 
            "Start: " + (reservation.getTourPackage() != null ? reservation.getTourPackage().getStart_date() : "null") + 
            ", End: " + (reservation.getTourPackage() != null ? reservation.getTourPackage().getEnd_date() : "null"));

        return ReservationResponseDTO.builder()
                .reservationId(reservation.getReservationId())
                .userId(reservation.getUser().getUserId())
                .userName(reservation.getUser().getName() + " " + reservation.getUser().getPaternalSurname())
                .packageId(reservation.getTourPackage().getPackageId())
                .packageTitle(reservation.getTourPackage().getTitle())
                .numberOfAdults(reservation.getNumberOfAdults())
                .numberOfChildren(reservation.getNumberOfChildren())
                .numberOfInfants(reservation.getNumberOfInfants())
                .totalAmount(reservation.getTotalAmount())
                .confirmationStatus(reservation.getConfirmationStatus())
                .rating(reservation.getRating())
                .createdAt(reservation.getCreatedAt())
                .updatedAt(reservation.getUpdatedAt())
                .startDate(reservation.getTourPackage().getStart_date())
                .endDate(reservation.getTourPackage().getEnd_date())
                .build();
    }

    public Reservation toEntity(ReservationRequestDTO requestDTO) {
        return Reservation.builder()
                .numberOfAdults(requestDTO.getNumberOfAdults())
                .numberOfChildren(requestDTO.getNumberOfChildren())
                .numberOfInfants(requestDTO.getNumberOfInfants())
                .build();
    }

    public void updateEntity(Reservation reservation, ReservationRequestDTO requestDTO) {
        reservation.setNumberOfAdults(requestDTO.getNumberOfAdults());
        reservation.setNumberOfChildren(requestDTO.getNumberOfChildren());
        reservation.setNumberOfInfants(requestDTO.getNumberOfInfants());
        // El totalAmount se calcula en el servicio
        if (requestDTO.getConfirmationStatus() != null) {
            reservation.setConfirmationStatus(requestDTO.getConfirmationStatus());
        }
        if (requestDTO.getRating() != null) {
            reservation.setRating(requestDTO.getRating());
        }
    }
}