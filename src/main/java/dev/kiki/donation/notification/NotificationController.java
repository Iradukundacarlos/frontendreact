package dev.kiki.donation.notification;

import dev.kiki.donation.notification.dto.NotificationRequest;
import dev.kiki.donation.notification.dto.UserNotificationResponse;
import dev.kiki.donation.user.UserService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
@SecurityRequirement(name = "auth")
@Tag(name = "Notification controller")
public class NotificationController {

    private final NotificationService notificationService;
    private final UserService userService;

    @PostMapping
    public ResponseEntity<Notification> createNotification(
            @Valid @RequestBody NotificationRequest notificationRequest
            ) {
        var newNotification =  notificationService.createAndSendNotification(notificationRequest.title(), notificationRequest.message());

        return new ResponseEntity<>(newNotification, HttpStatus.CREATED);
    }

    @GetMapping
    public ResponseEntity<List<UserNotificationResponse>> getAllNotifications() {
        List<UserNotification> notifications = notificationService.getUserNotifications(userService.getAuthenticatedUserId());

        List<UserNotificationResponse> response = notifications.stream()
                .map(n -> new UserNotificationResponse(
                        n.getNotification().getId(),
                        n.getNotification().getTitle(),
                        n.getNotification().getMessage(),
                        n.getIsRead(),
                        n.getNotification().getCreatedAt()
                )).toList();

        return ResponseEntity.ok(response);

    }

    @PostMapping("/{notificationId}/read")
    public ResponseEntity<String> readNotification(
            @PathVariable(name = "notificationId") Long notificationId
    ) {
        notificationService.markNotificationAsRead( userService.getAuthenticatedUserId(), notificationId);

        return ResponseEntity.ok("Notification marked as read.");
    }

}
