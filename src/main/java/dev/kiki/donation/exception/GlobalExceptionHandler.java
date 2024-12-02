package dev.kiki.donation.exception;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(org.springframework.web.bind.MethodArgumentNotValidException ex) {
        var errors = new HashMap<String, String>();
        ex.getBindingResult().getAllErrors()
                .forEach((error) -> {
                    String fieldName = ((FieldError) error).getField();
                    String message = error.getDefaultMessage();
                    errors.put(fieldName, message);
                });

        ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                400,
                "Validation failed",
                "Invalid input fields",
                errors
        );

        return ResponseEntity.badRequest().body(errorResponse);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                404,
                "Resource Not Found",
                ex.getMessage()
        );

        return ResponseEntity.status(404).body(errorResponse);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrityException(DataIntegrityViolationException ex) {
        Map<String, String> errors = new HashMap<>();
        String message = ex.getMostSpecificCause().getMessage();

        if (message.contains("users_email_key")) {
            errors.put("email", "Email is already taken");
        }
        if (message.contains("users_user_name_key")) {
            errors.put("userName", "Username is already taken");
        }
        if (message.contains("users_phone_number_key")) {
            errors.put("phoneNumber", "Phone number is already taken");
        }

        ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                400,
                "Validation Failed",
                "Invalid input fields",
                errors
        );

        return ResponseEntity.badRequest().body(errorResponse);
    }


    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneralException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                500,
                "Internal Server Error",
                ex.getMessage()
        );

        return ResponseEntity.status(500).body(errorResponse);
    }

}
