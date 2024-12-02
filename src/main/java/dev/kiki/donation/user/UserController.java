package dev.kiki.donation.user;

import dev.kiki.donation.user.dto.RegisterResponseDto;
import dev.kiki.donation.user.dto.UpdateDto;
import dev.kiki.donation.user.dto.UserInfo;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@SecurityRequirement(name = "auth")
@Tag(name = "User Controller")
public class UserController {
    private final UserService userService;
    private final UserRepository userRepository;

    @GetMapping("/export")
    public ResponseEntity<byte[]> exportUsers() {

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));

        byte[] csvData = userService.exportUsersToCSV();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=users_" + timestamp + ".csv");
        headers.add(HttpHeaders.CONTENT_TYPE, "text/csv");

        return new ResponseEntity<>(csvData, headers, HttpStatus.OK);
    }

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<User>> getAllUsers(HttpServletRequest request) {
        try {
            List<User> users = userRepository.findAll();
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @PutMapping("/{userId}")
    public ResponseEntity<RegisterResponseDto> updateUser(
            @PathVariable(name = "userId") Long userId,
            @RequestBody UpdateDto updateDto

    ) {
        var updatedUser = userService.updateUser(userId, updateDto);
        UserInfo userInfo = new UserInfo(
                updatedUser.getId(),
                updatedUser.getEmail(),
                updatedUser.getUsername(),
                updatedUser.getFirstName(),
                updatedUser.getLastName(),
                updatedUser.getRole());
        RegisterResponseDto response = new RegisterResponseDto(
                "User updated successfully",
                userInfo);
        return ResponseEntity.ok(response);

    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable(name = "userId") Long userId) {
        userService.deleteUser(userId);

        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/import")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> importUsers(@RequestParam("file") MultipartFile file) {
        try {
            if (!file.getContentType().equals("text/csv")) {
                return ResponseEntity
                        .badRequest()
                        .body("Please upload a CSV file");
            }

            int importedCount = userService.importUsersFromCSV(file);
            return ResponseEntity.ok(importedCount + " users successfully imported");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to import users: " + e.getMessage());
        }
    }
}
