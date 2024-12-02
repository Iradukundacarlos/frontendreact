package dev.kiki.donation.auth;

import dev.kiki.donation.user.User;
import dev.kiki.donation.user.UserRepository;
import dev.kiki.donation.user.UserService;
import dev.kiki.donation.user.dto.LoginDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;

    public User authenticateUser(LoginDto loginDto) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDto.email(),
                        loginDto.password()
                )
        );

        return userRepository.findByEmail(loginDto.email())
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

}
