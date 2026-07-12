import React, { useState } from 'react';
import { useApi } from '../lib/api';

// One entry per committed ledger transaction that touched a thesis —
// mirrors what GET /theses/:thesisId/history returns (main.go), which
// wraps chaincode.go's GetThesisHistory. Unlike the thesis object itself,
// this is a full audit trail: every DRAFT -> DEFENDED -> NOTARIZED step
// shows up as its own entry, with the txId that committed it.
export interface ThesisHistoryEntry {
  txId: string;
  timestamp: string;
  isDelete: boolean;
  value: {
    status?: string;
    grade?: string;
    hashDocument?: string;
    hashPv?: string;
    [key: string]: unknown;
  } | null;
}

// The two rooms (Registry/light, Defense Hall/dark) use different color
// tokens, so this component takes a `variant` rather than hardcoding one.
type Variant = 'light' | 'dark';

const styles: Record<Variant, { border: string; dim: string; text: string; headBg: string; link: string }> = {
  light: {
    border: 'border-[var(--parchment-line)]',
    dim: 'text-[var(--ink-soft)]',
    text: 'text-[var(--ink)]',
    headBg: 'bg-[var(--parchment-line)]/20',
    link: 'text-[var(--ink-soft)] hover:text-[var(--ink)]',
  },
  dark: {
    border: 'border-[var(--hall-line)]',
    dim: 'text-[var(--hall-text-dim)]',
    text: 'text-[var(--hall-text)]',
    headBg: 'bg-white/5',
    link: 'text-[var(--hall-text-dim)] hover:text-[var(--hall-text)]',
  },
};

export const TransactionHistory = ({ thesisId, variant = 'dark' }: { thesisId: string; variant?: Variant }) => {
  const api = useApi();
  const s = styles[variant];

  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<ThesisHistoryEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api(`/theses/${thesisId}/history`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to load transaction history');
      // Most recent transaction first.
      const sorted = [...(data || [])].sort(
        (a: ThesisHistoryEntry, b: ThesisHistoryEntry) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );
      setEntries(sorted);
    } catch (err: any) {
      setError(err.message || 'Failed to load transaction history');
    } finally {
      setLoading(false);
    }
  };

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && entries === null) load();
  };

  return (
    <div>
      <button
        type="button"
        onClick={toggle}
        className={`font-body text-xs underline underline-offset-2 ${s.link} transition-colors`}
      >
        {open ? 'Hide transaction details' : 'View transaction details'}
      </button>

      {open && (
        <div className={`mt-2 border ${s.border} rounded-sm overflow-hidden`}>
          {loading && <p className={`px-3 py-2 text-xs font-body ${s.dim}`}>Loading ledger history…</p>}

          {error && <p className="px-3 py-2 text-xs font-body text-[var(--seal)]">{error}</p>}

          {entries && entries.length === 0 && !loading && (
            <p className={`px-3 py-2 text-xs font-body ${s.dim}`}>No transactions recorded yet.</p>
          )}

          {entries && entries.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-data">
                <thead>
                  <tr className={`${s.headBg} text-left`}>
                    <th className={`px-3 py-1.5 font-medium ${s.dim}`}>Tx ID</th>
                    <th className={`px-3 py-1.5 font-medium ${s.dim}`}>Timestamp</th>
                    <th className={`px-3 py-1.5 font-medium ${s.dim}`}>Status</th>
                    <th className={`px-3 py-1.5 font-medium ${s.dim}`}>Grade</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => (
                    <tr key={e.txId} className={`border-t ${s.border}`}>
                      <td className={`px-3 py-1.5 ${s.text}`} title={e.txId}>
                        {e.txId.slice(0, 10)}…
                      </td>
                      <td className={`px-3 py-1.5 ${s.dim}`}>{new Date(e.timestamp).toLocaleString()}</td>
                      <td className={`px-3 py-1.5 ${s.dim}`}>{e.isDelete ? 'DELETED' : e.value?.status || '—'}</td>
                      <td className={`px-3 py-1.5 ${s.dim}`}>{e.value?.grade || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
