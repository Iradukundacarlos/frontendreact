package dev.kiki.donation;

import dev.kiki.donation.user.Role;
import dev.kiki.donation.user.User;
import dev.kiki.donation.user.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {
        return args -> {
            String adminEmail = "admin@gmail.com";
            
            // Check if admin user already exists
            if (userRepository.findByEmail(adminEmail).isEmpty()) {
                User user = new User();
                user.setFirstName("Derrick");
                user.setLastName("Nuby");
                user.setRole(Role.ROLE_ADMIN);
                user.setEmail(adminEmail);
                user.setPhoneNumber("+250788530944");
                user.setUserName("DerrickNuby");
                user.setPassword(passwordEncoder.encode("admin123@#"));

                userRepository.save(user);
            }
        };
    }

}
