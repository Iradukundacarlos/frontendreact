package dev.kiki.donation.user.dto;

public record RegisterResponseDto(
        String message,
        UserInfo user
) {}
