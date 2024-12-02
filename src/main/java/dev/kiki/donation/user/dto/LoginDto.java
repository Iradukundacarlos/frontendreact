package dev.kiki.donation.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginDto(

        @Email(message = "Enter a valid email")
        @NotBlank(message = "Email is required")
        String email,

        @NotBlank(message = "Email is required")
        String password
) {}
