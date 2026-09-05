import React, { useEffect, useState } from 'react';
import { StatusBar } from 'expo-status-bar';
import { Provider as PaperProvider, DefaultTheme } from 'react-native-paper';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { getToken } from './src/utils/storage';
import { LoginScreen } from './src/screens/LoginScreen';
import { AppNavigator } from './src/navigation/AppNavigator';
import { registerForPushNotificationsAsync } from './src/services/push';

const theme = {
  ...DefaultTheme,
  colors: { ...DefaultTheme.colors, primary: '#0a1f44' },
};

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null);

  useEffect(() => {
    getToken().then((t) => setAuthed(!!t));
  }, []);

  useEffect(() => {
    if (authed) registerForPushNotificationsAsync().catch(() => {});
  }, [authed]);

  if (authed === null) return null;

  return (
    <SafeAreaProvider>
      <PaperProvider theme={theme}>
        <StatusBar style="light" />
        {authed ? (
          <AppNavigator onLogout={() => setAuthed(false)} />
        ) : (
          <LoginScreen onLoggedIn={() => setAuthed(true)} />
        )}
      </PaperProvider>
    </SafeAreaProvider>
  );
}
