package dev.kiki.donation.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record UpdateDto(
        String firstName,

        String lastName,

        @Size(min = 5, max = 20, message = "Username must be between 5 and 20 characters long")
        String userName,

        @Email(message = "Enter a valid email")
        String email,

        String phoneNumber
) {}
