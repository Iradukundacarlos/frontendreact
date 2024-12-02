package dev.kiki.donation.user.dto;

public record UserResponseDto(
        Long id,
        String firstName,
        String lastName,

        String userName,

        String email,
        String phoneNumber
) {}
