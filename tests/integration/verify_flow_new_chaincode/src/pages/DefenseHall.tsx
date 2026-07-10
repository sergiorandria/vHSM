import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useApi, Thesis, JuryStatusInfo } from '../lib/api';
import { Seal, SealPhase } from '../components/Seal';

// What, if anything, the logged-in juror still owes on a given thesis.
// A thesis can need more than one of these at once (e.g. still needs my
// PV signature AND nobody has notarized the document yet), so callers
// should check all three rather than treating this as exclusive.
type Need = {
  grade: boolean;
  pvSignature: boolean;
  document: boolean;
};

const needsFor = (t: Thesis, username: string | null): Need => {
  const members = t.administrative?.juryMembers || [];
  const isJuror = !!username && members.includes(username);

  const alreadyGraded = !!username && (t.juryGrades || []).some((g) => g.jurorId === username);
  const alreadySigned = !!username && (t.pvSignatures || []).some((s) => s.jurorId === username);

  return {
    grade: t.status === 'DRAFT' && isJuror && !alreadyGraded,
    pvSignature: t.status === 'DEFENDED' && isJuror && !alreadySigned,
    // Document notarization isn't gated to a specific juror on the
    // chaincode side (NotarizeDocument doesn't check jurorID) — any jury
    // member can be the one who uploads the final manuscript, so this
    // only depends on the thesis's own state, not who "isJuror" is.
    document: t.status === 'DEFENDED' && isJuror && !t.hashDocument,
  };
};

const hasAnyNeed = (n: Need) => n.grade || n.pvSignature || n.document;

export const DefenseHall = () => {
  const api = useApi();
  const { logout, username } = useAuth();
  const navigate = useNavigate();

  const [docket, setDocket] = useState<Thesis[]>([]);
  const [selected, setSelected] = useState<Thesis | null>(null);
  const [juryStatus, setJuryStatus] = useState<JuryStatusInfo | null>(null);

  const [grade, setGrade] = useState('');
  const [comment, setComment] = useState('');
  const [pvFile, setPvFile] = useState<File | null>(null);
  const [docFile, setDocFile] = useState<File | null>(null);

  const [phase, setPhase] = useState<SealPhase>('idle');
  const [resultHash, setResultHash] = useState<string | undefined>(undefined);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<'grade' | 'pv' | 'document' | null>(null);

  const loadDocket = () => {
    api('/theses')
      .then((r) => r.json())
      .then((data: Thesis[]) => setDocket((data || []).filter((t) => hasAnyNeed(needsFor(t, username)))))
      .catch(() => setDocket([]));
  };

  const loadJuryStatus = (thesisId: string) => {
    api(`/theses/${thesisId}/jury-status`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setJuryStatus(data))
      .catch(() => setJuryStatus(null));
  };

  useEffect(() => {
    loadDocket();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectCase = (t: Thesis) => {
    setSelected(t);
    setPhase('idle');
    setResultHash(undefined);
    setError('');
    setGrade('');
    setComment('');
    setPvFile(null);
    setDocFile(null);
    loadJuryStatus(t.thesisId);
  };

  // Refetches the selected thesis + jury status + docket after any
  // mutation, so the UI reflects consensus state rather than a locally
  // guessed one (e.g. whether the thesis just flipped to DEFENDED).
  const refreshAfterMutation = (thesisId: string) => {
    loadDocket();
    loadJuryStatus(thesisId);
    api(`/theses/${thesisId}`)
      .then((r) => r.json())
      .then((t: Thesis) => setSelected(t))
      .catch(() => {});
  };

  const need = selected ? needsFor(selected, username) : null;

  const handleGrade = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    if (!grade) return setError('Enter a grade before submitting.');

    setError('');
    setBusy('grade');
    setPhase('pressing');
    try {
      const res = await api(`/theses/${selected.thesisId}/grades`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grade, comment }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Grade submission rejected');
      setPhase('sealed');
      refreshAfterMutation(selected.thesisId);
    } catch (err: any) {
      setError(err.message);
      setPhase('failed');
    } finally {
      setBusy(null);
    }
  };

  const handleSignPv = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    // The first signer must attach the PV file — every signer after that
    // reads the already-recorded hash off the ledger, per main.go's
    // /pv-signature handler.
    const firstSigner = !selected.hashPv;
    if (firstSigner && !pvFile) return setError('As the first signer, attach the procès-verbal file.');

    setError('');
    setBusy('pv');
    setPhase('pressing');
    try {
      const formData = new FormData();
      if (pvFile) formData.append('Pv', pvFile);

      const res = await api(`/theses/${selected.thesisId}/pv-signature`, { method: 'POST', body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Signature rejected');
      setResultHash(data.hashPv);
      setPhase('sealed');
      refreshAfterMutation(selected.thesisId);
    } catch (err: any) {
      setError(err.message);
      setPhase('failed');
    } finally {
      setBusy(null);
    }
  };

  const handleNotarizeDocument = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    if (!docFile) return setError('Attach the final manuscript to notarize it.');

    setError('');
    setBusy('document');
    setPhase('pressing');
    try {
      const formData = new FormData();
      formData.append('Document', docFile);

      const res = await api(`/theses/${selected.thesisId}/document`, { method: 'POST', body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Notarization rejected');
      setResultHash(data.document?.hash);
      setPhase('sealed');
      refreshAfterMutation(selected.thesisId);
    } catch (err: any) {
      setError(err.message);
      setPhase('failed');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--hall)]">
      <header className="bg-[var(--hall-panel)] border-b border-[var(--hall-line)]">
        <div className="max-w-5xl mx-auto px-6 py-4 flex justify-between items-center">
          <div>
            <h1 className="font-display text-xl text-[var(--hall-text)] tracking-wide">The Defense Hall</h1>
            <p className="font-body text-xs text-[var(--hall-text-dim)] mt-0.5">
              Judgement &amp; notarization {username && <>· signed in as <span className="font-data">{username}</span></>}
            </p>
          </div>
          <button
            onClick={() => {
              logout();
              navigate('/');
            }}
            className="font-body text-xs border border-[var(--hall-line)] text-[var(--hall-text)] px-3 py-1.5 rounded-sm hover:bg-white/5 transition-colors"
          >
            Sign out
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10 grid grid-cols-1 lg:grid-cols-5 gap-8">
        {/* --- Docket --- */}
        <section className="lg:col-span-2 hall-panel p-5 h-fit">
          <div className="flex justify-between items-center mb-4">
            <h2 className="font-display text-base text-[var(--hall-text)]">Docket</h2>
            <button
              onClick={loadDocket}
              className="font-body text-xs border border-[var(--hall-line)] px-2 py-1 rounded-sm text-[var(--hall-text-dim)] hover:bg-white/5 transition-colors"
            >
              Refresh
            </button>
          </div>
          <ul className="space-y-2">
            {docket.map((t) => {
              const n = needsFor(t, username);
              return (
                <li key={t.thesisId}>
                  <button
                    onClick={() => selectCase(t)}
                    className={`w-full text-left px-3 py-2.5 rounded-sm border transition-colors font-body text-sm ${
                      selected?.thesisId === t.thesisId
                        ? 'border-[var(--gold)] bg-[var(--gold)]/10'
                        : 'border-[var(--hall-line)] hover:border-[var(--hall-text-dim)]'
                    }`}
                  >
                    <div className="font-data text-xs text-[var(--gold)]">{t.thesisId}</div>
                    <div className="text-[var(--hall-text)] mt-0.5">{t.student?.fullName || 'Unnamed candidate'}</div>
                    <div className="text-[var(--hall-text-dim)] text-xs mt-0.5 truncate">{t.metadata?.title}</div>
                    <div className="flex gap-1.5 mt-1.5 flex-wrap">
                      {n.grade && (
                        <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded-full border border-[var(--gold)]/50 text-[var(--gold)]">
                          Grade due
                        </span>
                      )}
                      {n.pvSignature && (
                        <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded-full border border-[var(--seal)]/50 text-[var(--seal)]">
                          PV signature due
                        </span>
                      )}
                      {n.document && (
                        <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded-full border border-[var(--hall-text-dim)]/50 text-[var(--hall-text-dim)]">
                          Manuscript pending
                        </span>
                      )}
                    </div>
                  </button>
                </li>
              );
            })}
            {docket.length === 0 && (
              <li className="text-[var(--hall-text-dim)] font-body text-sm text-center py-8">
                No dossiers awaiting your action.
              </li>
            )}
          </ul>
        </section>

        {/* --- Case detail --- */}
        <section className="lg:col-span-3 hall-panel p-6">
          {!selected ? (
            <>
              <h2 className="font-display text-base text-[var(--hall-text)] mb-1">Notarize Defense</h2>
              <p className="font-body text-xs text-[var(--hall-text-dim)]">
                Select a dossier from the docket to begin.
              </p>
            </>
          ) : (
            <div className="space-y-8">
              <div>
                <h2 className="font-display text-base text-[var(--hall-text)] mb-1">
                  <span className="font-data text-[var(--gold)]">{selected.thesisId}</span> — {selected.student?.fullName}
                </h2>
                <p className="font-body text-xs text-[var(--hall-text-dim)]">{selected.metadata?.title}</p>
              </div>

              {juryStatus && (
                <div className="grid grid-cols-2 gap-3 font-body text-xs text-[var(--hall-text-dim)]">
                  <div className="border border-[var(--hall-line)] rounded-sm px-3 py-2">
                    <span className="text-[var(--hall-text)]">{juryStatus.gradesIn}</span> / {juryStatus.required} graded
                    {juryStatus.pendingGraders && juryStatus.pendingGraders.length > 0 && (
                      <div className="mt-1 truncate">awaiting: {juryStatus.pendingGraders.join(', ')}</div>
                    )}
                  </div>
                  <div className="border border-[var(--hall-line)] rounded-sm px-3 py-2">
                    <span className="text-[var(--hall-text)]">{juryStatus.pvSignaturesIn}</span> / {juryStatus.required} PV
                    signed
                    {juryStatus.pendingSigners && juryStatus.pendingSigners.length > 0 && (
                      <div className="mt-1 truncate">awaiting: {juryStatus.pendingSigners.join(', ')}</div>
                    )}
                  </div>
                </div>
              )}

              {error && (
                <div className="text-sm font-body text-[#e7b3ba] bg-[var(--seal)]/10 border border-[var(--seal)]/30 px-3 py-2 rounded-sm">
                  {error}
                </div>
              )}

              {/* --- Grade submission --- */}
              {need?.grade && (
                <form onSubmit={handleGrade} className="space-y-3 pt-2 border-t border-[var(--hall-line)]">
                  <h3 className="font-display text-sm text-[var(--hall-text)] pt-4">Your grade</h3>
                  <input
                    className="hall-input"
                    placeholder="Grade (e.g. 16.5)"
                    value={grade}
                    onChange={(e) => setGrade(e.target.value)}
                    required
                  />
                  <textarea
                    className="hall-input"
                    placeholder="Comment (optional)"
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    rows={2}
                  />
                  <button type="submit" disabled={busy === 'grade'} className="seal-button">
                    {busy === 'grade' ? 'Submitting…' : 'Submit grade'}
                  </button>
                  <p className="text-xs font-body text-[var(--hall-text-dim)]">
                    The defense is only recorded as complete once every assigned jury member has graded it.
                  </p>
                </form>
              )}

              {/* --- PV co-signing --- */}
              {need?.pvSignature && (
                <form onSubmit={handleSignPv} className="space-y-3 pt-4 border-t border-[var(--hall-line)]">
                  <h3 className="font-display text-sm text-[var(--hall-text)]">Sign the procès-verbal</h3>
                  {selected.hashPv ? (
                    <p className="font-body text-xs text-[var(--hall-text-dim)]">
                      A PV is already on record for this thesis (hash{' '}
                      <span className="font-data">{selected.hashPv.slice(0, 10)}…</span>). Signing here adds your
                      signature over that same document.
                    </p>
                  ) : (
                    <>
                      <label className="block text-xs text-[var(--hall-text-dim)] font-body mb-1">
                        Procès-verbal (PV) — you are the first signer, so attach the file
                      </label>
                      <input
                        type="file"
                        className="hall-input cursor-pointer"
                        onChange={(e) => setPvFile(e.target.files?.[0] || null)}
                        required
                      />
                    </>
                  )}
                  <button type="submit" disabled={busy === 'pv'} className="seal-button">
                    {busy === 'pv' ? 'Signing…' : 'Sign PV'}
                  </button>
                </form>
              )}

              {/* --- Document notarization --- */}
              {need?.document && (
                <form onSubmit={handleNotarizeDocument} className="space-y-3 pt-4 border-t border-[var(--hall-line)]">
                  <h3 className="font-display text-sm text-[var(--hall-text)]">Notarize the manuscript</h3>
                  <label className="block text-xs text-[var(--hall-text-dim)] font-body mb-1">Final manuscript (PDF)</label>
                  <input
                    type="file"
                    className="hall-input cursor-pointer"
                    onChange={(e) => setDocFile(e.target.files?.[0] || null)}
                    required
                  />
                  <button type="submit" disabled={busy === 'document'} className="seal-button">
                    {busy === 'document' ? 'Sealing…' : 'Notarize manuscript'}
                  </button>
                </form>
              )}

              {selected.status === 'NOTARIZED' && (
                <p className="font-body text-sm text-[var(--hall-text-dim)] pt-4 border-t border-[var(--hall-line)]">
                  This thesis is fully notarized and committed to the ledger.
                </p>
              )}

              {need && !hasAnyNeed(need) && selected.status !== 'NOTARIZED' && (
                <p className="font-body text-sm text-[var(--hall-text-dim)] pt-4 border-t border-[var(--hall-line)]">
                  Nothing pending on this dossier for you right now.
                </p>
              )}

              {phase !== 'idle' && (
                <div className="pt-6 border-t border-[var(--hall-line)]">
                  <Seal phase={phase} hash={resultHash} />
                  {phase === 'sealed' && (
                    <p className="text-center font-body text-xs text-[var(--hall-text-dim)] mt-3">Recorded on the ledger.</p>
                  )}
                </div>
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
};
