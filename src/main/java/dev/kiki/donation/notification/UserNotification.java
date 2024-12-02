package dev.kiki.donation.notification;

import dev.kiki.donation.user.User;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

// Unidirectional @Many-to-Many relationship
@Entity
@Table(name = "user_notifications")
@Data
@NoArgsConstructor
public class UserNotification {
    @EmbeddedId
    UserNotificationKey id;

    @ManyToOne
    @MapsId("userId")
    User user;

    @ManyToOne
    @MapsId("notificationId")
    Notification notification;

    @Column(nullable = false)
    private Boolean isRead = false;

    private LocalDateTime readAt;


}
