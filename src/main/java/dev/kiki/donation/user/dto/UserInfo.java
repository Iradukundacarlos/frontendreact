package dev.kiki.donation.user.dto;

import dev.kiki.donation.user.Role;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserInfo {
    private Long id;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private Role role;
}
