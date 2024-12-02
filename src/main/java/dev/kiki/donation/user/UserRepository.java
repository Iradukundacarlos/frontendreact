package dev.kiki.donation.user;

import dev.kiki.donation.user.dto.UserResponseDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    @Query("""
        SELECT new dev.kiki.donation.user.dto.UserResponseDto(
            u.id, 
            u.firstName, 
            u.lastName, 
            u.userName, 
            u.email, 
            u.phoneNumber
        ) 
        FROM User u
    """)
    Page<UserResponseDto> findAllUsers(Pageable pageable);

}
