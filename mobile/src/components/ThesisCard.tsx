import React from 'react';
import { StyleSheet, View } from 'react-native';
import { Card, Chip, Text } from 'react-native-paper';
import { Thesis } from '../types';

const statusColor: Record<string, string> = {
  DRAFT: '#6c757d',
  DEFENDED: '#f0ad4e',
  NOTARIZED: '#28a745',
  ARCHIVED: '#6c757d',
};

export function ThesisCard({ thesis, onPress }: { thesis: Thesis; onPress?: () => void }) {
  return (
    <Card style={styles.card} onPress={onPress}>
      <Card.Title
        title={thesis.metadata?.title || thesis.thesisId}
        subtitle={`${thesis.student?.fullName || thesis.studentId} • ${thesis.administrative?.academicYear || ''}`}
        right={(props) => (
          <Chip
            {...props}
            style={[styles.chip, { backgroundColor: statusColor[thesis.status] || '#6c757d' }]}
            textStyle={{ color: 'white', fontSize: 11 }}
          >
            {thesis.status}
          </Chip>
        )}
      />
      <Card.Content>
        <View style={styles.row}>
          <Text variant="bodySmall">ID: {thesis.thesisId}</Text>
          <Text variant="bodySmall">Grade: {thesis.thesisGrade || '—'}</Text>
        </View>
        {thesis.metadata?.abstract ? (
          <Text variant="bodySmall" numberOfLines={2} style={styles.abstract}>
            {thesis.metadata.abstract}
          </Text>
        ) : null}
      </Card.Content>
    </Card>
  );
}

const styles = StyleSheet.create({
  card: { marginHorizontal: 12, marginVertical: 6 },
  chip: { marginRight: 12, height: 28 },
  row: { flexDirection: 'row', justifyContent: 'space-between', marginTop: 4 },
  abstract: { marginTop: 8, color: '#555' },
});
