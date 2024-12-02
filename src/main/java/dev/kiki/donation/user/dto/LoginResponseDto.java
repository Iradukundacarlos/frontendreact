package dev.kiki.donation.user.dto;

import java.util.Map;

public record LoginResponseDto(
        String message,
        String accessToken,
        Map<String, Object> user,
        Long expiresIn
) {}
