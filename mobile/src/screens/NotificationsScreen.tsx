import React from 'react';
import { FlatList, RefreshControl, StyleSheet, View } from 'react-native';
import { ActivityIndicator, Text, Button } from 'react-native-paper';
import { useNotifications } from '../hooks/useNotifications';
import { NotificationCard } from '../components/NotificationCard';

export function NotificationsScreen({ navigation }: any) {
  const { items, loading, refresh } = useNotifications();

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator />
        <Text style={styles.hint}>Listening for push…</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.banner}>
        <Text variant="bodySmall" style={styles.bannerText}>
          🔔 Notifications appear directly in your system tray — even when the app is backgrounded.
          Pull to refresh or wait for FCM push.
        </Text>
      </View>
      <FlatList
        data={items}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <NotificationCard
            item={item}
            onPress={() => item.thesisId && navigation.navigate('ThesisDetail', { thesisId: item.thesisId })}
          />
        )}
        refreshControl={<RefreshControl refreshing={false} onRefresh={refresh} />}
        ListEmptyComponent={
          <View style={styles.center}>
            <Text>No notifications yet — you will be notified on SIGN_CREATED, LEDGER_COMMITTED, etc.</Text>
            <Button mode="outlined" onPress={refresh} style={{ marginTop: 12 }}>
              Refresh
            </Button>
          </View>
        }
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f7fb' },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 },
  hint: { marginTop: 8, color: '#666' },
  banner: { backgroundColor: '#0a1f44', padding: 10 },
  bannerText: { color: 'white', textAlign: 'center' },
});
