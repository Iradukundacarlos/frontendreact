package dev.kiki.donation.user;

import dev.kiki.donation.exception.ResourceNotFoundException;
import dev.kiki.donation.user.dto.RegisterDto;
import dev.kiki.donation.user.dto.UpdateDto;
import dev.kiki.donation.user.dto.UserResponseDto;
import lombok.RequiredArgsConstructor;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println(username);
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    public Long getAuthenticatedUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof AnonymousAuthenticationToken)) {
            String userName = auth.getName();
            var user = userRepository.findByEmail(userName)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));
            return user.getId();
        } else {
            throw new RuntimeException("User not found");
        }
    }

    public User createUser(RegisterDto registerDto) {
        User user = new User();
        user.setFirstName(registerDto.firstName());
        user.setLastName(registerDto.lastName());
        user.setUserName(registerDto.email());
        user.setEmail(registerDto.email());
        user.setPhoneNumber(registerDto.phoneNumber());
        user.setRole(Role.ROLE_USER);
        user.setPassword(passwordEncoder.encode(registerDto.password()));

        return userRepository.save(user);

    }

    public byte[] exportUsersToCSV() {
        List<User> users = userRepository.findAll();
        try (
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                OutputStreamWriter writer = new OutputStreamWriter(out, StandardCharsets.UTF_8);
                CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT.builder()
                        .setHeader("ID", "First Name", "Last Name", "Username", "Email", "Phone Number", "Role",
                                "Created At", "Updated At")
                        .build())) {

            for (User user : users) {
                csvPrinter.printRecord(
                        user.getId(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getPhoneNumber(),
                        user.getRole().name(),
                        user.getCreatedAt(),
                        user.getUpdatedAt());
            }

            csvPrinter.flush();
            return out.toByteArray();

        } catch (IOException e) {
            throw new RuntimeException("Error while exporting users to CSV " + e);
        }
    }

    public Page<UserResponseDto> findAll(Pageable pageable) {
        return userRepository.findAllUsers(pageable);
    }

    public User updateUser(Long userId, UpdateDto updateDto) {
        var existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User is not found"));
        if (updateDto.firstName() != null) {
            existingUser.setFirstName(updateDto.firstName());
        }
        if (updateDto.lastName() != null) {
            existingUser.setLastName(updateDto.lastName());
        }
        if (updateDto.userName() != null) {
            existingUser.setUserName(updateDto.userName());
        }
        if (updateDto.email() != null) {
            existingUser.setEmail(updateDto.email());
        }
        if (updateDto.phoneNumber() != null) {
            existingUser.setPhoneNumber(updateDto.phoneNumber());
        }

        return userRepository.save(existingUser);

    }

    public void deleteUser(Long userId) {
        var existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User is not found"));

        userRepository.delete(existingUser);
    }

    public int importUsersFromCSV(MultipartFile file) {
        try {
            CSVFormat csvFormat = CSVFormat.DEFAULT.builder()
                    .setHeader("ID", "First Name", "Last Name", "Username", "Email", "Phone Number", "Role",
                            "Created At", "Updated At")
                    .setSkipHeaderRecord(true)
                    .build();

            List<User> users = CSVParser
                    .parse(new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8), csvFormat)
                    .getRecords()
                    .stream()
                    .map(record -> {
                        User user = new User();
                        user.setFirstName(record.get("First Name"));
                        user.setLastName(record.get("Last Name"));
                        user.setUserName(record.get("Username"));
                        user.setEmail(record.get("Email"));
                        user.setPhoneNumber(record.get("Phone Number"));
                        user.setRole(Role.valueOf(record.get("Role")));
                        user.setPassword(passwordEncoder.encode("12345678"));
                        return user;
                    })
                    .toList();

            userRepository.saveAll(users);
            return users.size();
        } catch (IOException e) {
            throw new RuntimeException("Error while importing users from CSV: " + e.getMessage(), e);
        }
    }

}
