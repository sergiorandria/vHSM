import * as Device from 'expo-device';
import * as Notifications from 'expo-notifications';
import Constants from 'expo-constants';
import { Platform } from 'react-native';
import { registerDevice } from './api';

// Show notifications while app is foregrounded as well
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
    shouldShowBanner: true,
    shouldShowList: true,
  }),
});

export async function registerForPushNotificationsAsync(): Promise<string | null> {
  // SDK 53+ : remote push removed from Expo Go — detect and degrade gracefully
  const isExpoGo = Constants.appOwnership === 'expo';
  if (isExpoGo) {
    console.log(
      '[push] Running in Expo Go — remote push (FCM) is disabled since SDK 53. ' +
        'Local polling + scheduleLocalNotification will still show tray alerts. ' +
        'For true FCM push use a development build: npx expo run:android / eas build.'
    );
  }

  if (!Device.isDevice) {
    console.log('Must use physical device for Push Notifications');
    return null;
  }

  const { status: existingStatus } = await Notifications.getPermissionsAsync();
  let finalStatus = existingStatus;
  if (existingStatus !== 'granted') {
    const { status } = await Notifications.requestPermissionsAsync();
    finalStatus = status;
  }
  if (finalStatus !== 'granted') {
    console.log('Failed to get push token permission');
    return null;
  }

  // In Expo Go, skip remote token — local notifications via polling are used
  if (isExpoGo) {
    console.log('[push] Expo Go: skipping remote token, using local polling');
    return null;
  }

  const projectId = Constants.expoConfig?.extra?.eas?.projectId;
  let token: string | null = null;
  try {
    const t = await Notifications.getExpoPushTokenAsync(
      projectId ? { projectId } : undefined
    );
    token = t.data;
  } catch (e) {
    console.log('Expo push token failed, trying FCM:', e);
    try {
      const t = await Notifications.getDevicePushTokenAsync();
      token = t.data as unknown as string;
    } catch (e2) {
      console.log('[push] FCM token also unavailable (Expo Go):', e2);
      return null;
    }
  }

  if (Platform.OS === 'android') {
    await Notifications.setNotificationChannelAsync('vhsm-critical', {
      name: 'vHSM Critical',
      importance: Notifications.AndroidImportance.MAX,
      vibrationPattern: [0, 250, 250, 250],
      lightColor: '#FF0000',
    });
    await Notifications.setNotificationChannelAsync('vhsm-default', {
      name: 'vHSM',
      importance: Notifications.AndroidImportance.DEFAULT,
    });
  }

  if (token) {
    try {
      await registerDevice(token, Platform.OS);
      console.log('Registered FCM token with backend');
    } catch (e) {
      console.log('Backend device registration failed (will retry):', e);
    }
  }

  return token;
}

export function addNotificationListeners(
  onReceived: (n: Notifications.Notification) => void,
  onResponse: (r: Notifications.NotificationResponse) => void
) {
  const sub1 = Notifications.addNotificationReceivedListener(onReceived);
  const sub2 = Notifications.addNotificationResponseReceivedListener(onResponse);
  return () => {
    sub1.remove();
    sub2.remove();
  };
}

export async function scheduleLocalNotification(
  title: string,
  body: string,
  data: Record<string, unknown> = {}
) {
  await Notifications.scheduleNotificationAsync({
    content: { title, body, data, sound: true },
    trigger: null,
  });
}
