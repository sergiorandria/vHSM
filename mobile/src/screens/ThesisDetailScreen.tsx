import React, { useEffect, useState } from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import { ActivityIndicator, Button, Card, Chip, Divider, Text } from 'react-native-paper';
import { fetchThesis, fetchJuryStatus, fetchHistory } from '../services/api';
import { JuryStatus, Thesis } from '../types';

export function ThesisDetailScreen({ route, navigation }: any) {
  const { thesisId } = route.params;
  const [thesis, setThesis] = useState<Thesis | null>(null);
  const [jury, setJury] = useState<JuryStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const raw = await fetchThesis(thesisId);
        const t = typeof raw === 'string' ? JSON.parse(raw) : raw;
        // API returns raw bytes; handle both
        const parsed: Thesis = t.thesis || t;
        setThesis(parsed);
      } catch {}
      try {
        const j = await fetchJuryStatus(thesisId);
        setJury(j);
      } catch {}
      setLoading(false);
    })();
  }, [thesisId]);

  if (loading || !thesis) {
    return (
      <View style={styles.center}>
        <ActivityIndicator />
      </View>
    );
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={{ paddingBottom: 24 }}>
      <Card style={styles.card}>
        <Card.Title title={thesis.metadata?.title || thesisId} subtitle={thesis.status} />
        <Card.Content>
          <Text variant="bodyMedium">Student: {thesis.student?.fullName || thesis.studentId}</Text>
          <Text variant="bodySmall">Thesis ID: {thesis.thesisId}</Text>
          <Text variant="bodySmall">Grade: {thesis.thesisGrade || '— pending jury'}</Text>
          {thesis.hashPv ? <Text variant="bodySmall">PV hash: {thesis.hashPv.slice(0, 32)}…</Text> : null}
        </Card.Content>
      </Card>

      {jury ? (
        <Card style={styles.card}>
          <Card.Title title="Jury progress" />
          <Card.Content>
            <Text>
              Grades: {jury.gradesIn}/{jury.required} • PV signatures: {jury.pvSignaturesIn}/{jury.required}
            </Text>
            {jury.pendingGraders?.length ? <Text>Pending graders: {jury.pendingGraders.join(', ')}</Text> : null}
            {jury.pendingSigners?.length ? <Text>Pending signers: {jury.pendingSigners.join(', ')}</Text> : null}
            <View style={styles.chips}>
              <Chip icon="check" style={styles.chip}>
                {thesis.status}
              </Chip>
            </View>
          </Card.Content>
        </Card>
      ) : null}

      <Card style={styles.card}>
        <Card.Content>
          <Button mode="outlined" onPress={() => navigation.navigate('History', { thesisId })}>
            View transaction history
          </Button>
          <Button mode="contained" style={{ marginTop: 8 }} onPress={() => navigation.navigate('Proof', { thesisId })}>
            Verify proof
          </Button>
        </Card.Content>
      </Card>

      <Divider style={{ marginVertical: 12 }} />
      <Text variant="bodySmall" style={styles.hint}>
        All actions are ledger-anchored. Co-signing the PV requires every jury member to sign
        the same HashPv — enforced on-chain.
      </Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f7fb' },
  card: { margin: 12 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  chips: { flexDirection: 'row', marginTop: 8 },
  chip: { backgroundColor: '#e3f2fd' },
  hint: { textAlign: 'center', color: '#777', paddingHorizontal: 16 },
});
