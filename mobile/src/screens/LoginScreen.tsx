import React, { useState } from 'react';
import { StyleSheet, View, Image, KeyboardAvoidingView, Platform, Alert } from 'react-native';
import { Button, Text, TextInput, Card } from 'react-native-paper';
import { login } from '../services/api';
import { saveToken, saveUser } from '../utils/storage';
import { registerForPushNotificationsAsync } from '../services/push';

export function LoginScreen({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    if (!username || !password) {
      Alert.alert('Missing fields', 'Username and password are required');
      return;
    }
    setLoading(true);
    try {
      const res = await login(username, password);
      await saveToken(res.token);
      await saveUser(res.username, res.roles);
      // Fire-and-forget push registration — must not block login
      registerForPushNotificationsAsync().catch(() => {});
      onLoggedIn();
    } catch (e: any) {
      Alert.alert('Login failed', e.response?.data?.error || e.message || 'Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      style={styles.container}
    >
      <View style={styles.header}>
        <Text variant="headlineMedium" style={styles.title}>
          vHSM Mobile
        </Text>
        <Text variant="bodyMedium" style={styles.subtitle}>
          Thesis notarization — on your phone
        </Text>
      </View>

      <Card style={styles.card}>
        <Card.Content>
          <TextInput
            label="Username (LDAP)"
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
            autoCorrect={false}
            style={styles.input}
          />
          <TextInput
            label="Password"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            style={styles.input}
          />
          <Button mode="contained" onPress={handleLogin} loading={loading} style={styles.button}>
            Sign in
          </Button>
          <Text variant="bodySmall" style={styles.hint}>
            Uses the same LDAP/JWT as the web UI and REST API. Notifications will appear
            directly in your system tray after login.
          </Text>
        </Card.Content>
      </Card>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0a1f44', justifyContent: 'center', padding: 20 },
  header: { alignItems: 'center', marginBottom: 32 },
  title: { color: 'white', fontWeight: '700' },
  subtitle: { color: '#b0c4de', marginTop: 6 },
  card: { borderRadius: 16 },
  input: { marginBottom: 12, backgroundColor: 'white' },
  button: { marginTop: 8, paddingVertical: 4, backgroundColor: '#0a1f44' },
  hint: { marginTop: 12, color: '#666', textAlign: 'center' },
});
