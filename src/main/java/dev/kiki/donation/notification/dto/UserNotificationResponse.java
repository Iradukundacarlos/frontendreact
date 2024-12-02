package dev.kiki.donation.notification.dto;

import java.time.LocalDateTime;

public record UserNotificationResponse(
        Long id,
        String title,
        String message,
        Boolean isRead,
        LocalDateTime createdAt
) {}
