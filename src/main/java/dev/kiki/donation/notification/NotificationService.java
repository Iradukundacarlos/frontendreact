package dev.kiki.donation.notification;

import dev.kiki.donation.exception.ResourceNotFoundException;
import dev.kiki.donation.user.User;
import dev.kiki.donation.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NotificationService {
    private final NotificationRepository notificationRepository;
    private final UserNotificationRepository userNotificationRepository;
    private final UserRepository userRepository;

    public Notification createAndSendNotification(String title, String message) {

        Notification notification = new Notification();
        notification.setTitle(title);
        notification.setMessage(message);
        notification.setStatus(NotificationStatus.SENT);
        var newNotification = notificationRepository.save(notification);

        List<User> users = userRepository.findAll();
        for (User user: users) {
            UserNotification userNotification = new UserNotification();
            userNotification.setId(new UserNotificationKey(user.getId(), newNotification.getId()));
            userNotification.setUser(user);
            userNotification.setNotification(newNotification);
            userNotificationRepository.save(userNotification);
        }

        return newNotification;
    }

    public List<UserNotification> getUserNotifications(Long userId) {
        return userNotificationRepository.findByUserId(userId);
    }

    public void markNotificationAsRead(Long userId, Long notificationId) {
        UserNotificationKey userNotificationKey = new UserNotificationKey(userId, notificationId);
        UserNotification userNotification = userNotificationRepository.findById(userNotificationKey)
                .orElseThrow(() -> new ResourceNotFoundException("Notification not found for user"));
        userNotification.setIsRead(true);
        userNotification.setReadAt(LocalDateTime.now());
        userNotificationRepository.save(userNotification);
    }

}
