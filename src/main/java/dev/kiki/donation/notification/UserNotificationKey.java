package dev.kiki.donation.notification;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Embeddable
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserNotificationKey implements Serializable {
    private Long userId;
    private Long notificationId;
}
