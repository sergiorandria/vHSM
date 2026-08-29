import { useCallback, useEffect, useRef, useState } from 'react';
import * as Notifications from 'expo-notifications';
import { fetchHistory, fetchTheses } from '../services/api';
import { addNotificationListeners, scheduleLocalNotification } from '../services/push';
import { NotificationItem } from '../types';

function mapHistoryToNotifications(history: any[], thesisId: string): NotificationItem[] {
  if (!Array.isArray(history)) return [];
  return history.map((h: any, idx: number) => ({
    id: h.txId || `${thesisId}-${idx}`,
    type: h.isDelete ? 'DELETED' : 'LEDGER_COMMIT',
    severity: 'INFO' as const,
    timestamp: h.timestamp ? new Date(h.timestamp).getTime() : Date.now(),
    source: 'ledger',
    actor: h.value?.createdBy || 'system',
    summary: h.isDelete ? `Thesis ${thesisId} deleted` : `Thesis ${thesisId} updated — tx ${h.txId?.slice(0, 8)}`,
    detail: h.value,
    thesisId,
  }));
}

export function useNotifications(pollIntervalMs = 30_000) {
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const seenRef = useRef<Set<string>>(new Set());

  const poll = useCallback(async () => {
    try {
      const raw = await fetchTheses();
      const theses: any[] = Array.isArray(raw) ? raw : raw.theses || [];
      const all: NotificationItem[] = [];
      for (const t of theses.slice(0, 20)) {
        const id = t.thesisId || t.thesis_id || t.id;
        if (!id) continue;
        try {
          const hist = await fetchHistory(id);
          const arr = Array.isArray(hist) ? hist : [];
          all.push(...mapHistoryToNotifications(arr, id));
        } catch {}
      }
      // Sort newest first
      all.sort((a, b) => b.timestamp - a.timestamp);
      // Fire local notification for unseen
      for (const n of all.slice(0, 5)) {
        if (!seenRef.current.has(n.id)) {
          seenRef.current.add(n.id);
          // Only notify for items newer than last poll (avoid spam on first load)
          if (seenRef.current.size > 5) {
            await scheduleLocalNotification(n.summary, `vHSM • ${n.type}`, { thesisId: n.thesisId });
          }
        }
      }
      setItems(all.slice(0, 50));
    } catch (e) {
      console.log('poll notifications failed', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    poll();
    const id = setInterval(poll, pollIntervalMs);
    const unsub = addNotificationListeners(
      (n) => {
        const data = n.request.content.data as any;
        // Push from FCM already shows banner via handler; just refresh list
        poll();
      },
      (r) => {
        // Deep link handled by navigator
        console.log('notification response', r.notification.request.content.data);
      }
    );
    return () => {
      clearInterval(id);
      unsub();
    };
  }, [poll, pollIntervalMs]);

  return { items, loading, refresh: poll };
}
