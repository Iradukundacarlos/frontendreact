package dev.kiki.donation.notification.dto;

import jakarta.validation.constraints.NotBlank;

public record NotificationRequest(
        @NotBlank(message = "Notification title is required")
        String title,

        @NotBlank(message = "Notification message is required")
        String message
) {}
