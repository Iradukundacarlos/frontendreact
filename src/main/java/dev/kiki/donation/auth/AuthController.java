package dev.kiki.donation.auth;

import dev.kiki.donation.auth.jwt.JwtService;
import dev.kiki.donation.user.User;
import dev.kiki.donation.user.UserService;
import dev.kiki.donation.user.dto.*;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
@Tag(name = "Authentication Controller")
public class AuthController {
        @Autowired
        private final UserService userService;
        @Autowired
        private final AuthService authService;
        @Autowired
        private final JwtService jwtService;

        @PostMapping("/sign-up")
        public ResponseEntity<RegisterResponseDto> register(
                        @Valid @RequestBody RegisterDto registerDto) {
                try {
                        var newUser = userService.createUser(registerDto);

                        UserInfo userInfo = new UserInfo(
                                        newUser.getId(),
                                        newUser.getEmail(),
                                        newUser.getUsername(),
                                        newUser.getFirstName(),
                                        newUser.getLastName(),
                                        newUser.getRole());

                        RegisterResponseDto response = new RegisterResponseDto(
                                        "Registration successful",
                                        userInfo);

                        return ResponseEntity.ok(response);

                        
                } catch (Exception e) {
                        System.err.println("Unexpected error during registration: " + e.getMessage());
                        e.printStackTrace();
                        return ResponseEntity
                                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(new RegisterResponseDto("An unexpected error occurred", null));
                }
        }

        @PostMapping("/login")
        public ResponseEntity<LoginResponseDto> login(@Valid @RequestBody LoginDto loginDto) {
                try {
                        User authenticatedUser = authService.authenticateUser(loginDto);
                        String accessToken = jwtService.generateToken(authenticatedUser);

                        Map<String, Object> user = Map.of(
                                        "id", authenticatedUser.getId(),
                                        "email", authenticatedUser.getEmail(),
                                        "username", authenticatedUser.getUsername(),
                                        "role", authenticatedUser.getRole().name(),
                                        "name",
                                        authenticatedUser.getFirstName() + " " + authenticatedUser.getLastName());

                        LoginResponseDto loginResponse = new LoginResponseDto(
                                        "Login Successful",
                                        accessToken,
                                        user,
                                        jwtService.expirationTime());

                        return ResponseEntity.ok(loginResponse);
                } catch (UsernameNotFoundException e) {
                        LoginResponseDto errorResponse = new LoginResponseDto(
                                        "User not found",
                                        null,
                                        null,
                                        null);
                        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
                } catch (BadCredentialsException e) {
                        LoginResponseDto errorResponse = new LoginResponseDto(
                                        "Invalid email or password",
                                        null,
                                        null,
                                        null);
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
                } catch (DisabledException e) {
                        LoginResponseDto errorResponse = new LoginResponseDto(
                                        "Account is disabled",
                                        null,
                                        null,
                                        null);
                        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
                } catch (LockedException e) {
                        LoginResponseDto errorResponse = new LoginResponseDto(
                                        "Account is locked",
                                        null,
                                        null,
                                        null);
                        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
                } catch (Exception e) {
                        LoginResponseDto errorResponse = new LoginResponseDto(
                                        "An unexpected error occurred",
                                        null,
                                        null,
                                        null);
                        System.out.println(e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
                }
        }

        @PostMapping("/logout")
        public ResponseEntity<Map<String, String>> logout(
                        @RequestHeader(name = "Authorization") String authHeader) {
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                        .body(Map.of("message", "Invalid token format"));
                }
                String token = authHeader.substring(7);

                jwtService.invalidateToken(token);

                return ResponseEntity.ok(Map.of("message", "Logout successful"));
        }

}
