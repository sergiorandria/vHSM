# vHSM Mobile — Direct Push Notifications

React Native (Expo SDK 52) app that surfaces **vHSM thesis & HSM events directly on the phone** as system notifications. No polling-only web view — real `FCM` push via `expo-notifications`.

## Features

* **System push** — `SIGN_CREATED`, `LEDGER_COMMITTED`, `LEDGER_COMMIT_FAILED`, `INTEGRITY_ALERT`, `PIN_LOCKOUT`, etc. appear in the notification tray even when the app is backgrounded/killed.
* **JWT auth** — reuses `rest_api` LDAP/JWT (`POST /api/v1/login`); token stored in `expo-secure-store`.
* **Thesis flow** — list, detail, jury grading progress (`GET /api/v1/theses`, `/jury-status`, `/history`), PV co-sign, document notarization — same permissions as web.
* **Proof & audit** — `GET /api/v1/proof/:recordId` and `GET /api/v1/audit/tail` rendered natively.
* **Notifications inbox** — polling fallback every 30s (`GET /api/v1/theses/:id/history` aggregated) + FCM push; tapping a push deep-links to the thesis.
* **Offline** — `expo-secure-store` caches JWT + last theses; `date-fns` relative times.

## Quick start

```bash
cd mobile
npm install
# point at your rest_api (or set EXPO_PUBLIC_API_URL)
echo "EXPO_PUBLIC_API_URL=http://10.0.2.2:8080" > .env
npx expo start
# scan QR with Expo Go (Android) or Camera (iOS)
```

Build APK/AAB:

```bash
npm run build:android   # EAS
npx expo prebuild && npx expo run:android  # bare
```

## Push setup

1. `npx expo install expo-notifications expo-device`
2. Firebase project → `google-services.json` (Android) / `GoogleService-Info.plist` (iOS) → `mobile/` root.
3. Backend env `FCM_SERVER_KEY` or `FIREBASE_PROJECT_ID` + service-account JSON; the new `MobilePushAdapter` (`src/notification/mobile_push_adapter.{h,cpp}`) sends to `https://fcm.googleapis.com/fcm/send` via `libcurl` (same pattern as `webhook_adapter`). Device tokens are registered via `POST /api/v1/mobile/devices` (see `rest_api/internal/mobile_service.go`).
4. App calls `registerForPushNotificationsAsync()` on login, posts token to `/api/v1/mobile/devices`, and listens with `Notifications.addNotificationReceivedListener`.

## Structure

```
mobile/
  src/
    navigation/AppNavigator.tsx — stack + bottom tabs, deep link vhsm://thesis/:id
    screens/LoginScreen, HomeScreen, ThesisDetailScreen, NotificationsScreen, HistoryScreen, SettingsScreen
    services/api.ts — axios + JWT interceptor, services/push.ts — FCM registration & listeners
    hooks/useNotifications.ts — polling + push merge
    components/ThesisCard, NotificationCard
```

## Backend wiring

* `src/notification/mobile_push_adapter.{h,cpp}` — channel `mobile_push` / `fcm`, `ISubscriber.address` = FCM token
* `src/notification/CMakeLists.txt` + `src/pkcs11/composition_root.cpp` — wires adapter into `NotificationDispatcher`
* `rest_api/internal/mobile_service.go` + `rest_api/cmd/api/main.go` — `POST /api/v1/mobile/devices`, `DELETE`, `GET /api/v1/mobile/notifications`

All push failures are at-most-once retried by the dispatcher (WARN/CRITICAL retries), same as email/webhook.
