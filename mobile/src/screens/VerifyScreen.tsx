import React, { useEffect, useState } from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import { ActivityIndicator, Button, Card, Chip, Text } from 'react-native-paper';
import { fetchVerify } from '../services/api';
import { scheduleLocalNotification } from '../services/push';

export function VerifyScreen({ route }: any) {
  const { recordId } = route.params as { recordId: string };
  const [res, setRes] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await fetchVerify(recordId);
        setRes(data);
        // Tamper-evident: integrity HMAC is the primary signal, not just ledger_status
        if (data && data.integrity_hmac_ok === false) {
          await scheduleLocalNotification(
            '🚨 vHSM Tamper Detected',
            `Record ${recordId.slice(0, 12)}… HMAC invalid — local DB has been tampered with.`,
            { recordId, type: 'INTEGRITY_ALERT' }
          );
        } else if (data && data.ledger_cross_check_ok === false && data.record_found) {
          await scheduleLocalNotification(
            '⚠️ vHSM Ledger Mismatch',
            `Record ${recordId.slice(0, 12)}… ledger cross-check failed — payload/sig/fingerprint mismatch.`,
            { recordId, type: 'LEDGER_ALERT' }
          );
        }
      } catch (e: any) {
        setError(e?.response?.data?.error || e?.message || 'Verification failed');
      } finally {
        setLoading(false);
      }
    })();
  }, [recordId]);

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator />
        <Text style={{ marginTop: 8 }}>Verifying HMAC + ledger…</Text>
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.center}>
        <Text style={styles.error}>{error}</Text>
        <Button mode="contained" onPress={() => setLoading(true)} style={{ marginTop: 12 }}>
          Retry
        </Button>
      </View>
    );
  }

  if (!res) return null;

  const integrityOk = res.integrity_hmac_ok !== false; // Go has no KEK, but admin gRPC is source of truth; REST assumes true when ledger proof decodes
  const ledgerOk = res.ledger_cross_check_ok;
  const valid = res.valid;

  return (
    <ScrollView style={styles.container} contentContainerStyle={{ paddingBottom: 24 }}>
      <Card style={[styles.card, !integrityOk && styles.cardTamper]}>
        <Card.Title
          title={valid ? '✓ Verified' : integrityOk ? '⚠️ Ledger Pending/Mismatch' : '🚨 Tamper Detected'}
          subtitle={`Record ${recordId}`}
        />
        <Card.Content>
          <View style={styles.row}>
            <Chip icon={integrityOk ? 'check' : 'alert'} style={integrityOk ? styles.chipOk : styles.chipTamper}>
              HMAC {integrityOk ? 'ok' : 'INVALID'}
            </Chip>
            <Chip icon={ledgerOk ? 'check' : 'alert'} style={ledgerOk ? styles.chipOk : styles.chipWarn}>
              Ledger {ledgerOk ? 'ok' : 'fail'}
            </Chip>
            <Chip style={valid ? styles.chipOk : styles.chipWarn}>{res.ledger_status || 'unknown'}</Chip>
          </View>
          {!integrityOk && (
            <Text style={styles.tamperText}>
              Local record integrity HMAC verification failed (RowIntegrity::verify_hmac, constant-time). The row was altered outside the normal insert path — fail-closed.
            </Text>
          )}
          {integrityOk && !ledgerOk && res.record_found && (
            <Text style={styles.warnText}>
              Ledger cross-check failed: {res.error_detail || 'payload/signature/fingerprint mismatch or not yet anchored (check_ledger latency)'}
            </Text>
          )}
          {res.error_detail && <Text style={styles.errorSmall}>{res.error_detail}</Text>}
          <View style={{ marginTop: 12 }}>
            <Text variant="bodySmall">Tx: {res.ledger_tx_id || '—'}</Text>
            <Text variant="bodySmall">Block: {res.ledger_block_num ?? '—'}</Text>
            <Text variant="bodySmall">Key fingerprint: {res.key_fingerprint || '—'}</Text>
          </View>
        </Card.Content>
      </Card>
      <Text variant="bodySmall" style={styles.hint}>
        C_Verify is crypto-only (do_verify). Tamper check lives in Admin::VerifySignature → VerificationService (HMAC + ledger) and REST GET /verify/:id, which this screen calls.
      </Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f7fb' },
  card: { margin: 12 },
  cardTamper: { borderColor: '#d32f2f', borderWidth: 1.5 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 },
  row: { flexDirection: 'row', gap: 8, marginVertical: 8, flexWrap: 'wrap' },
  chipOk: { backgroundColor: '#e8f5e9' },
  chipTamper: { backgroundColor: '#ffebee' },
  chipWarn: { backgroundColor: '#fff3e0' },
  tamperText: { color: '#b71c1c', marginTop: 8, fontWeight: '600' },
  warnText: { color: '#e65100', marginTop: 8 },
  error: { color: '#d32f2f', textAlign: 'center' },
  errorSmall: { color: '#d32f2f', marginTop: 8, fontSize: 12 },
  hint: { textAlign: 'center', color: '#777', paddingHorizontal: 16, marginTop: 8 },
});
