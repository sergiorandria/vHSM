import React from 'react';
import { StyleSheet, View } from 'react-native';
import { Card, Chip, Text } from 'react-native-paper';
import { formatDistanceToNow } from 'date-fns';
import { NotificationItem } from '../types';

const severityColor = {
  INFO: '#17a2b8',
  WARNING: '#ffc107',
  CRITICAL: '#dc3545',
};

export function NotificationCard({ item, onPress }: { item: NotificationItem; onPress?: () => void }) {
  return (
    <Card style={styles.card} onPress={onPress}>
      <Card.Content>
        <View style={styles.header}>
          <Chip
            compact
            textStyle={{ color: 'white', fontSize: 10 }}
            style={{ backgroundColor: severityColor[item.severity] || '#6c757d', height: 24 }}
          >
            {item.severity}
          </Chip>
          <Text variant="labelSmall" style={styles.time}>
            {formatDistanceToNow(new Date(item.timestamp), { addSuffix: true })}
          </Text>
        </View>
        <Text variant="titleSmall" style={styles.summary}>
          {item.summary}
        </Text>
        <Text variant="bodySmall" style={styles.meta}>
          {item.type} • {item.source} • {item.actor}
        </Text>
      </Card.Content>
    </Card>
  );
}

const styles = StyleSheet.create({
  card: { marginHorizontal: 12, marginVertical: 4 },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  time: { color: '#666' },
  summary: { marginTop: 8 },
  meta: { marginTop: 4, color: '#777' },
});
