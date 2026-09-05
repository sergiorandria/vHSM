import React, { useEffect, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { Button, Card, Text, TextInput } from 'react-native-paper';
import { API_URL } from '../utils/config';
import { clearToken, getUser } from '../utils/storage';

export function SettingsScreen({ onLogout }: { onLogout: () => void }) {
  const [user, setUser] = useState<{ username: string; roles: string[] } | null>(null);

  useEffect(() => {
    getUser().then(setUser);
  }, []);

  return (
    <View style={styles.container}>
      <Card style={styles.card}>
        <Card.Title title="Account" />
        <Card.Content>
          <Text>Username: {user?.username || '—'}</Text>
          <Text>Roles: {user?.roles?.join(', ') || '—'}</Text>
          <Text variant="bodySmall" style={styles.hint}>
            Authenticated via LDAP/JWT — same as web. Token stored in SecureStore.
          </Text>
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Connection" />
        <Card.Content>
          <TextInput label="API URL" value={API_URL} disabled style={styles.input} />
          <Text variant="bodySmall" style={styles.hint}>
            Set EXPO_PUBLIC_API_URL at build time to point at your rest_api (default localhost:8080).
            For Android emulator use http://10.0.2.2:8080
          </Text>
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Push" />
        <Card.Content>
          <Text variant="bodySmall">
            Channel: mobile_push (FCM) — registered automatically on login. Disable in system
            Settings → Notifications → vHSM Mobile if needed. Critical events use high-importance channel.
          </Text>
        </Card.Content>
      </Card>

      <Button mode="contained" buttonColor="#b00020" onPress={async () => { await clearToken(); onLogout(); }} style={styles.logout}>
        Log out
      </Button>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f7fb', padding: 12 },
  card: { marginBottom: 12 },
  input: { backgroundColor: 'white' },
  hint: { marginTop: 8, color: '#666' },
  logout: { marginTop: 12 },
});
