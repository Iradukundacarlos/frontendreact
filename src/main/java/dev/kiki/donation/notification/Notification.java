package dev.kiki.donation.notification;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "notifications")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    String title;

    String message;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    NotificationStatus status = NotificationStatus.SENT;

    @CreationTimestamp
    @Column(nullable = false)
    LocalDateTime createdAt;


}
