package dev.kiki.donation.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterDto(

                @NotBlank(message = "First name is required") String firstName,

                @NotBlank(message = "Last name is required") String lastName,

                // @NotBlank(message = "Username is required") @Size(min = 5, max = 20, message
                // = "Username must be between 5 and 20 characters long") String userName,

                @Email(message = "Enter a valid email") @NotBlank(message = "Email is required") String email,

                @NotBlank(message = "Phone number is required") String phoneNumber,

                @NotBlank(message = "Password is required") @Size(min = 8, message = "Password must be at least 8 characters long") String password,

                @NotBlank(message = "Confirm password is required") @Size(min = 8, message = "Password must be at least 8 characters long") String confirmPassword) {
}
