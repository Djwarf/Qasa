package common

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// NotificationType represents different types of notifications
type NotificationType string

const (
	NotificationInfo    NotificationType = "info"
	NotificationSuccess NotificationType = "success"
	NotificationWarning NotificationType = "warning"
	NotificationError   NotificationType = "error"
)

// Notification represents a single notification
type Notification struct {
	ID        string           `json:"id"`
	Title     string           `json:"title"`
	Message   string           `json:"message"`
	Type      NotificationType `json:"type"`
	Timestamp time.Time        `json:"timestamp"`
	Read      bool             `json:"read"`
	Persistent bool            `json:"persistent"` // If true, won't auto-expire
}

// NotificationManager manages notifications across the application
type NotificationManager struct {
	notifications []Notification
	subscribers   map[string]NotificationSubscriber
	mutex         sync.RWMutex
	maxRetained   int
}

// NotificationSubscriber defines the interface for notification subscribers
type NotificationSubscriber interface {
	OnNotification(notification Notification)
}

// NotificationChannel is a channel-based subscriber implementation
type NotificationChannel struct {
	Channel chan Notification
}

func (nc *NotificationChannel) OnNotification(notification Notification) {
	select {
	case nc.Channel <- notification:
	default:
		// Channel full, drop notification
		log.Printf("Warning: Notification channel full, dropping notification: %s", notification.Title)
	}
}

// NewNotificationManager creates a new notification manager
func NewNotificationManager(maxRetained int) *NotificationManager {
	if maxRetained <= 0 {
		maxRetained = 100 // Default maximum retained notifications
	}
	
	return &NotificationManager{
		notifications: make([]Notification, 0, maxRetained),
		subscribers:   make(map[string]NotificationSubscriber),
		maxRetained:   maxRetained,
	}
}

// AddNotification adds a new notification
func (nm *NotificationManager) AddNotification(title, message string, notificationType NotificationType) string {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	notification := Notification{
		ID:        GenerateID(),
		Title:     title,
		Message:   message,
		Type:      notificationType,
		Timestamp: time.Now(),
		Read:      false,
		Persistent: notificationType == NotificationError || notificationType == NotificationWarning,
	}
	
	// Add to the beginning of the slice
	nm.notifications = append([]Notification{notification}, nm.notifications...)
	
	// Trim to max retained if necessary
	if len(nm.notifications) > nm.maxRetained {
		nm.notifications = nm.notifications[:nm.maxRetained]
	}
	
	// Notify subscribers
	for _, subscriber := range nm.subscribers {
		go subscriber.OnNotification(notification)
	}
	
	return notification.ID
}

// Subscribe adds a notification subscriber
func (nm *NotificationManager) Subscribe(id string, subscriber NotificationSubscriber) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	nm.subscribers[id] = subscriber
}

// Unsubscribe removes a notification subscriber
func (nm *NotificationManager) Unsubscribe(id string) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	delete(nm.subscribers, id)
}

// GetNotifications returns all notifications
func (nm *NotificationManager) GetNotifications() []Notification {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	// Return a copy to prevent modification
	notifications := make([]Notification, len(nm.notifications))
	copy(notifications, nm.notifications)
	return notifications
}

// GetUnreadCount returns the number of unread notifications
func (nm *NotificationManager) GetUnreadCount() int {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	count := 0
	for _, notification := range nm.notifications {
		if !notification.Read {
			count++
		}
	}
	return count
}

// MarkAsRead marks a notification as read
func (nm *NotificationManager) MarkAsRead(id string) bool {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	for i := range nm.notifications {
		if nm.notifications[i].ID == id {
			nm.notifications[i].Read = true
			return true
		}
	}
	return false
}

// MarkAllAsRead marks all notifications as read
func (nm *NotificationManager) MarkAllAsRead() {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	for i := range nm.notifications {
		nm.notifications[i].Read = true
	}
}

// RemoveNotification removes a specific notification
func (nm *NotificationManager) RemoveNotification(id string) bool {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	for i, notification := range nm.notifications {
		if notification.ID == id {
			nm.notifications = append(nm.notifications[:i], nm.notifications[i+1:]...)
			return true
		}
	}
	return false
}

// ClearNotifications removes all notifications
func (nm *NotificationManager) ClearNotifications() {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	nm.notifications = nm.notifications[:0]
}

// ClearReadNotifications removes all read notifications
func (nm *NotificationManager) ClearReadNotifications() {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	unread := make([]Notification, 0, len(nm.notifications))
	for _, notification := range nm.notifications {
		if !notification.Read {
			unread = append(unread, notification)
		}
	}
	nm.notifications = unread
}

// CleanupExpiredNotifications removes old non-persistent notifications
func (nm *NotificationManager) CleanupExpiredNotifications(maxAge time.Duration) int {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	retained := make([]Notification, 0, len(nm.notifications))
	removed := 0
	
	for _, notification := range nm.notifications {
		if notification.Persistent || notification.Timestamp.After(cutoff) {
			retained = append(retained, notification)
		} else {
			removed++
		}
	}
	
	nm.notifications = retained
	return removed
}

// ToJSON serializes notifications to JSON
func (nm *NotificationManager) ToJSON() ([]byte, error) {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	return json.Marshal(nm.notifications)
}

// Convenience methods for different notification types

// Info adds an info notification
func (nm *NotificationManager) Info(title, message string) string {
	return nm.AddNotification(title, message, NotificationInfo)
}

// Success adds a success notification
func (nm *NotificationManager) Success(title, message string) string {
	return nm.AddNotification(title, message, NotificationSuccess)
}

// Warning adds a warning notification
func (nm *NotificationManager) Warning(title, message string) string {
	return nm.AddNotification(title, message, NotificationWarning)
}

// Error adds an error notification
func (nm *NotificationManager) Error(title, message string) string {
	return nm.AddNotification(title, message, NotificationError)
}

// Global notification manager instance
var globalNotificationManager *NotificationManager
var globalNotificationOnce sync.Once

// GetGlobalNotificationManager returns the global notification manager
func GetGlobalNotificationManager() *NotificationManager {
	globalNotificationOnce.Do(func() {
		globalNotificationManager = NewNotificationManager(100)
	})
	return globalNotificationManager
}

// Convenience functions using the global manager

// NotifyInfo adds a global info notification
func NotifyInfo(title, message string) string {
	return GetGlobalNotificationManager().Info(title, message)
}

// NotifySuccess adds a global success notification
func NotifySuccess(title, message string) string {
	return GetGlobalNotificationManager().Success(title, message)
}

// NotifyWarning adds a global warning notification
func NotifyWarning(title, message string) string {
	return GetGlobalNotificationManager().Warning(title, message)
}

// NotifyError adds a global error notification
func NotifyError(title, message string) string {
	return GetGlobalNotificationManager().Error(title, message)
} 