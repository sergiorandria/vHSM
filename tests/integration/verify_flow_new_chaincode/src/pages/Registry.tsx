import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useApi, Thesis } from '../lib/api';
import { TransactionHistory } from '../components/TransactionHistory';

const emptyDossier = () => ({
  thesisId: `TH-${Date.now()}`,
  studentId: '',
  student: {
    fullName: '',
    email: '',
    enrollmentYear: new Date().getFullYear(),
    program: '',
    department: '',
  },
  administrative: {
    institution: "Université d'Antananarivo",
    faculty: '',
    academicYear: '',
    supervisorName: '',
    juryMembers: [] as string[],
    defenseDate: '',
    registrationDate: new Date().toISOString(),
  },
  metadata: {
    title: '',
    language: 'fr',
    submittedAt: new Date().toISOString(),
  },
});

export const Registry = () => {
  const api = useApi();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [dossier, setDossier] = useState(emptyDossier());
  const [status, setStatus] = useState<{ kind: 'idle' | 'ok' | 'error'; message?: string }>({ kind: 'idle' });
  const [theses, setTheses] = useState<Thesis[]>([]);
  // Draft text for the "add a jury member" input — juryMembers itself
  // lives on dossier.administrative so it gets submitted with the rest of
  // the dossier. IDs here must match the LDAP usernames jurors log in
  // with, since that's what the chaincode checks submissions against.
  const [jurorDraft, setJurorDraft] = useState('');
  // Which thesisId (if any) has its transaction-details row expanded in
  // the ledger table below. Only one at a time to keep the table simple.
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const addJuror = () => {
    const id = jurorDraft.trim();
    if (!id) return;
    if (dossier.administrative.juryMembers.includes(id)) {
      setJurorDraft('');
      return;
    }
    setDossier({
      ...dossier,
      administrative: {
        ...dossier.administrative,
        juryMembers: [...dossier.administrative.juryMembers, id],
      },
    });
    setJurorDraft('');
  };

  const removeJuror = (id: string) => {
    setDossier({
      ...dossier,
      administrative: {
        ...dossier.administrative,
        juryMembers: dossier.administrative.juryMembers.filter((m) => m !== id),
      },
    });
  };

  const loadLedger = () => {
    api('/theses')
      .then((r) => r.json())
      .then((data) => setTheses(data || []))
      .catch(() => setTheses([]));
  };

  useEffect(() => {
    loadLedger();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus({ kind: 'idle' });
    if (dossier.administrative.juryMembers.length < 2) {
      setStatus({ kind: 'error', message: 'Assign at least two jury members before filing.' });
      return;
    }
    try {
      const res = await api('/theses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(dossier),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Filing failed');
      setStatus({ kind: 'ok', message: `Dossier ${data.thesisId ?? dossier.thesisId} filed to the ledger.` });
      setDossier(emptyDossier());
      loadLedger();
    } catch (err: any) {
      setStatus({ kind: 'error', message: err.message });
    }
  };

  return (
    <div className="min-h-screen bg-[var(--parchment)]">
      <header className="bg-[var(--ink)] text-[var(--parchment-soft)]">
        <div className="max-w-5xl mx-auto px-6 py-4 flex justify-between items-center">
          <div>
            <h1 className="font-display text-xl tracking-wide">The Registry</h1>
            <p className="font-body text-xs text-[var(--parchment-line)] mt-0.5">Pre-defense filing office</p>
          </div>
          <button
            onClick={() => {
              logout();
              navigate('/');
            }}
            className="font-body text-xs border border-[var(--parchment-line)]/60 text-[var(--parchment-soft)] px-3 py-1.5 rounded-sm hover:bg-white/5 transition-colors"
          >
            Sign out
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10 space-y-10">
        {/* --- Dossier filing form --- */}
        <section className="dossier-card p-8">
          <h2 className="font-display text-lg text-[var(--ink)] mb-6">New Dossier</h2>
          <form onSubmit={handleSubmit} className="space-y-8">
            {/* Art. I */}
            <fieldset className="space-y-3">
              <legend className="dossier-article-number mb-2">Art. I — Identity</legend>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <input
                  className="dossier-input"
                  placeholder="Student ID"
                  value={dossier.studentId}
                  onChange={(e) => setDossier({ ...dossier, studentId: e.target.value })}
                  required
                />
                <input
                  className="dossier-input"
                  placeholder="Full name"
                  value={dossier.student.fullName}
                  onChange={(e) => setDossier({ ...dossier, student: { ...dossier.student, fullName: e.target.value } })}
                  required
                />
                <input
                  className="dossier-input"
                  placeholder="Email"
                  type="email"
                  value={dossier.student.email}
                  onChange={(e) => setDossier({ ...dossier, student: { ...dossier.student, email: e.target.value } })}
                  required
                />
                <input
                  className="dossier-input"
                  placeholder="Enrollment year"
                  type="number"
                  value={dossier.student.enrollmentYear}
                  onChange={(e) =>
                    setDossier({ ...dossier, student: { ...dossier.student, enrollmentYear: Number(e.target.value) } })
                  }
                />
                <input
                  className="dossier-input"
                  placeholder="Program"
                  value={dossier.student.program}
                  onChange={(e) => setDossier({ ...dossier, student: { ...dossier.student, program: e.target.value } })}
                />
                <input
                  className="dossier-input"
                  placeholder="Department"
                  value={dossier.student.department}
                  onChange={(e) => setDossier({ ...dossier, student: { ...dossier.student, department: e.target.value } })}
                />
              </div>
            </fieldset>

            {/* Art. II */}
            <fieldset className="space-y-3">
              <legend className="dossier-article-number mb-2">Art. II — Institution</legend>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <input
                  className="dossier-input"
                  placeholder="Institution"
                  value={dossier.administrative.institution}
                  onChange={(e) =>
                    setDossier({ ...dossier, administrative: { ...dossier.administrative, institution: e.target.value } })
                  }
                />
                <input
                  className="dossier-input"
                  placeholder="Faculty"
                  value={dossier.administrative.faculty}
                  onChange={(e) =>
                    setDossier({ ...dossier, administrative: { ...dossier.administrative, faculty: e.target.value } })
                  }
                />
                <input
                  className="dossier-input"
                  placeholder="Academic year (e.g. 2025-2026)"
                  value={dossier.administrative.academicYear}
                  onChange={(e) =>
                    setDossier({ ...dossier, administrative: { ...dossier.administrative, academicYear: e.target.value } })
                  }
                />
                <input
                  className="dossier-input"
                  placeholder="Supervisor"
                  value={dossier.administrative.supervisorName}
                  onChange={(e) =>
                    setDossier({ ...dossier, administrative: { ...dossier.administrative, supervisorName: e.target.value } })
                  }
                />
                <div className="sm:col-span-2 space-y-2">
                  <span className="text-xs font-body text-[var(--ink-soft)]">
                    Jury members ({dossier.administrative.juryMembers.length})
                  </span>
                  <div className="flex gap-2">
                    <input
                      className="dossier-input"
                      placeholder="Juror username (LDAP)"
                      value={jurorDraft}
                      onChange={(e) => setJurorDraft(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          addJuror();
                        }
                      }}
                    />
                    <button
                      type="button"
                      onClick={addJuror}
                      className="shrink-0 px-4 rounded-sm border border-[var(--ink)] text-[var(--ink)] font-body text-sm hover:bg-[var(--ink)] hover:text-[var(--parchment-soft)] transition-colors"
                    >
                      Add
                    </button>
                  </div>
                  {dossier.administrative.juryMembers.length > 0 && (
                    <ul className="flex flex-wrap gap-2">
                      {dossier.administrative.juryMembers.map((m) => (
                        <li
                          key={m}
                          className="flex items-center gap-2 font-data text-xs bg-[var(--parchment-line)]/30 border border-[var(--parchment-line)] rounded-full px-3 py-1 text-[var(--ink)]"
                        >
                          {m}
                          <button
                            type="button"
                            onClick={() => removeJuror(m)}
                            aria-label={`Remove ${m} from jury`}
                            className="text-[var(--ink-soft)] hover:text-[var(--seal)]"
                          >
                            ✕
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                  <p className="text-xs font-body text-[var(--ink-soft)]/80">
                    The thesis is only marked defended once every one of these jurors has submitted a grade.
                  </p>
                </div>
                <label className="flex flex-col gap-1 sm:col-span-2">
                  <span className="text-xs font-body text-[var(--ink-soft)]">Scheduled defense date</span>
                  <input
                    className="dossier-input"
                    type="datetime-local"
                    onChange={(e) =>
                      setDossier({
                        ...dossier,
                        administrative: {
                          ...dossier.administrative,
                          defenseDate: e.target.value ? new Date(e.target.value).toISOString() : '',
                        },
                      })
                    }
                  />
                </label>
              </div>
            </fieldset>

            {/* Art. III */}
            <fieldset className="space-y-3">
              <legend className="dossier-article-number mb-2">Art. III — Manuscript</legend>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <input
                  className="dossier-input sm:col-span-2"
                  placeholder="Thesis title"
                  value={dossier.metadata.title}
                  onChange={(e) => setDossier({ ...dossier, metadata: { ...dossier.metadata, title: e.target.value } })}
                  required
                />
                <select
                  className="dossier-input"
                  value={dossier.metadata.language}
                  onChange={(e) => setDossier({ ...dossier, metadata: { ...dossier.metadata, language: e.target.value } })}
                >
                  <option value="fr">Français</option>
                  <option value="en">English</option>
                  <option value="mg">Malagasy</option>
                </select>
                <div className="dossier-input bg-[var(--parchment-line)]/20 text-[var(--ink-soft)] font-data text-xs flex items-center">
                  {dossier.thesisId}
                </div>
              </div>
            </fieldset>

            <button type="submit" className="registry-button">
              Inscribe Dossier
            </button>
          </form>

          {status.kind !== 'idle' && (
            <div
              className={`mt-5 text-sm font-body px-4 py-3 rounded-sm border ${
                status.kind === 'ok'
                  ? 'bg-emerald-900/10 border-emerald-700/30 text-emerald-800'
                  : 'bg-[var(--seal)]/10 border-[var(--seal)]/30 text-[var(--seal-dark)]'
              }`}
            >
              {status.message}
            </div>
          )}
        </section>

        {/* --- Ledger --- */}
        <section className="dossier-card overflow-hidden">
          <div className="flex justify-between items-center px-6 py-4 border-b border-[var(--parchment-line)]">
            <h2 className="font-display text-lg text-[var(--ink)]">Ledger</h2>
            <button
              onClick={loadLedger}
              className="font-body text-xs border border-[var(--parchment-line)] px-3 py-1.5 rounded-sm text-[var(--ink)] hover:bg-[var(--parchment-line)]/20 transition-colors"
            >
              Refresh
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm font-body">
              <thead>
                <tr className="text-left text-[var(--ink-soft)] uppercase text-xs tracking-wider">
                  <th className="px-6 py-2 font-medium">№</th>
                  <th className="px-6 py-2 font-medium">Candidate</th>
                  <th className="px-6 py-2 font-medium">Status</th>
                  <th className="px-6 py-2 font-medium">Jury</th>
                  <th className="px-6 py-2 font-medium">Grade</th>
                  <th className="px-6 py-2 font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {theses.map((t, i) => {
                  const required = t.administrative?.juryMembers?.length || 0;
                  const gradesIn = t.juryGrades?.length || 0;
                  const signaturesIn = t.pvSignatures?.length || 0;
                  const isExpanded = expandedId === t.thesisId;
                  return (
                    <React.Fragment key={t.thesisId ?? i}>
                      <tr className="border-t border-[var(--parchment-line)]/60 odd:bg-[var(--parchment-soft)]/60">
                        <td className="px-6 py-3 font-data text-xs text-[var(--ink-soft)]">{t.thesisId}</td>
                        <td className="px-6 py-3 text-[var(--ink)]">{t.student?.fullName || '—'}</td>
                        <td className="px-6 py-3">
                          <span
                            className={`inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border ${
                              t.status === 'DRAFT'
                                ? 'border-[var(--gold)]/50 text-[var(--gold)]'
                                : 'border-[var(--seal)]/50 text-[var(--seal)]'
                            }`}
                          >
                            <span
                              className={`w-1.5 h-1.5 rounded-full ${t.status === 'DRAFT' ? 'bg-[var(--gold)]' : 'bg-[var(--seal)]'}`}
                            />
                            {t.status}
                          </span>
                        </td>
                        <td className="px-6 py-3 font-data text-xs text-[var(--ink-soft)]">
                          {t.status === 'DRAFT' && `${gradesIn}/${required} graded`}
                          {t.status === 'DEFENDED' && `${signaturesIn}/${required} signed`}
                          {(t.status === 'NOTARIZED' || t.status === 'ARCHIVED') && `${required}/${required} complete`}
                        </td>
                        <td className="px-6 py-3 font-data text-xs text-[var(--ink-soft)]">{t.grade || '—'}</td>
                        <td className="px-6 py-3">
                          <button
                            type="button"
                            onClick={() => setExpandedId(isExpanded ? null : t.thesisId)}
                            className="font-body text-xs underline underline-offset-2 text-[var(--ink-soft)] hover:text-[var(--ink)] transition-colors"
                          >
                            {isExpanded ? 'Hide' : 'View'}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="border-t border-[var(--parchment-line)]/60 bg-[var(--parchment-soft)]/40">
                          <td colSpan={6} className="px-6 py-3">
                            <TransactionHistory thesisId={t.thesisId} variant="light" />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
            {theses.length === 0 && (
              <div className="text-center py-10 text-[var(--ink-soft)] font-body text-sm">
                No dossiers filed yet. Everything starts here.
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
};
