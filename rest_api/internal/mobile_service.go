package internal

import (
	"sync"
	"time"
)

// MobileDevice is a registered phone for push notifications.
// Stored in-memory for now; a production deployment would persist to DB
// via NotificationRepository (channel = "mobile_push", address = FCM token).
type MobileDevice struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	FCMToken  string `json:"fcm_token"`
	Platform  string `json:"platform"` // ios | android | expo
	CreatedAt int64  `json:"created_at"`
}

type MobileService struct {
	mu      sync.RWMutex
	devices map[string][]MobileDevice // username -> devices
}

func NewMobileService() *MobileService {
	return &MobileService{devices: make(map[string][]MobileDevice)}
}

func (s *MobileService) Register(username, fcmToken, platform string) MobileDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Deduplicate by token
	for _, d := range s.devices[username] {
		if d.FCMToken == fcmToken {
			return d
		}
	}
	dev := MobileDevice{
		ID:        username + ":" + fcmToken[:8],
		Username:  username,
		FCMToken:  fcmToken,
		Platform:  platform,
		CreatedAt: time.Now().UnixMilli(),
	}
	s.devices[username] = append(s.devices[username], dev)
	return dev
}

func (s *MobileService) Unregister(username, fcmToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.devices[username]
	out := list[:0]
	for _, d := range list {
		if d.FCMToken != fcmToken {
			out = append(out, d)
		}
	}
	s.devices[username] = out
}

func (s *MobileService) List(username string) []MobileDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]MobileDevice(nil), s.devices[username]...)
}

func (s *MobileService) AllTokens() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, list := range s.devices {
		for _, d := range list {
			out = append(out, d.FCMToken)
		}
	}
	return out
}
