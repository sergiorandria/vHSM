import React, { useEffect, useState } from 'react';
import { FlatList, StyleSheet, View } from 'react-native';
import { ActivityIndicator, Card, Text } from 'react-native-paper';
import { fetchHistory } from '../services/api';

export function HistoryScreen({ route }: any) {
  const { thesisId } = route.params;
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHistory(thesisId)
      .then((h) => setHistory(Array.isArray(h) ? h : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [thesisId]);

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <FlatList
        data={history}
        keyExtractor={(item, idx) => item.txId || String(idx)}
        renderItem={({ item }) => (
          <Card style={styles.card}>
            <Card.Content>
              <Text variant="titleSmall">Tx {String(item.txId).slice(0, 12)}…</Text>
              <Text variant="bodySmall">{item.timestamp}</Text>
              <Text variant="bodySmall">{item.isDelete ? 'DELETED' : 'COMMIT'}</Text>
            </Card.Content>
          </Card>
        )}
        ListEmptyComponent={
          <View style={styles.center}>
            <Text>No history yet</Text>
          </View>
        }
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f7fb' },
  card: { marginHorizontal: 12, marginVertical: 4 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 },
});
