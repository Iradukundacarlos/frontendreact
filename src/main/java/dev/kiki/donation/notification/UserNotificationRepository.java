package dev.kiki.donation.notification;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface UserNotificationRepository extends JpaRepository<UserNotification, UserNotificationKey> {
    List<UserNotification> findByUserId(Long userId);
}
