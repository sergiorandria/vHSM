import React, { useState, useEffect } from 'react'

const TOKEN_KEY = 'vhsm_jwt'

function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

async function api(path, token) {
  const res = await fetch(path, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }
  return { status: res.status, data }
}

function TokenBar({ token, setToken }) {
  const [value, setValue] = useState(token)
  useEffect(() => {
    setValue(token)
  }, [token])
  return (
    <div className="tokenbar">
      <label>JWT</label>
      <input
        type="text"
        placeholder="paste a token from /api/v1/login"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button
        onClick={() => {
          localStorage.setItem(TOKEN_KEY, value.trim())
          setToken(value.trim())
        }}
      >
        Save
      </button>
      {token && <span className="ok">saved</span>}
    </div>
  )
}

function Field({ label, value, mono }) {
  if (value === undefined || value === null || value === '') return null
  return (
    <div className="field">
      <span className="field-label">{label}</span>
      <span className={mono ? 'field-value mono' : 'field-value'}>{String(value)}</span>
    </div>
  )
}

function ProofPage({ token }) {
  const [recordId, setRecordId] = useState('')
  const [proof, setProof] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const verify = async () => {
    setError('')
    setProof(null)
    if (!recordId.trim()) {
      setError('Enter a recordId.')
      return
    }
    setLoading(true)
    try {
      const { status, data } = await api(`/api/v1/proof/${encodeURIComponent(recordId.trim())}`, token)
      if (status === 404) {
        setError('Signature record not found on the ledger.')
      } else if (status >= 400) {
        setError(data?.error || `Request failed (${status}).`)
      } else {
        setProof(data)
      }
    } catch (e) {
      setError('Network error: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  const anchored = proof && Number(proof.block_number) > 0

  return (
    <div className="page">
      <h2>Verify a signature</h2>
      <p className="muted">
        Look up a signature record anchored by the HSM on the Fabric ledger. The
        block number and transaction id prove when and where it was recorded.
      </p>
      <div className="row">
        <input
          type="text"
          placeholder="recordId (e.g. sig-0001)"
          value={recordId}
          onChange={(e) => setRecordId(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && verify()}
        />
        <button onClick={verify} disabled={loading}>
          {loading ? 'Verifying…' : 'Verify'}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {proof && (
        <div className="card">
          {anchored ? (
            <div className="badge ok">
              ✓ anchored in block {proof.block_number}{' '}
              {proof.tx_id ? `(tx ${proof.tx_id})` : ''}
            </div>
          ) : (
            <div className="badge warn">pending — not yet anchored in a block</div>
          )}
          <Field label="Record ID" value={proof.record_id} mono />
          <Field label="Key fingerprint" value={proof.key_fingerprint} mono />
          <Field label="Submitter" value={proof.submitter} />
          <Field label="Payload digest" value={proof.payload_digest} mono />
          <Field label="Signature (base64)" value={proof.signature_b64} mono />
          <Field
            label="Created at"
            value={proof.created_at ? new Date(Number(proof.created_at) * 1000).toLocaleString() : ''}
          />
          <Field label="Tx ID" value={proof.tx_id} mono />
          <Field label="Block number" value={proof.block_number} />
        </div>
      )}
    </div>
  )
}

function HistoryPage({ token }) {
  const [thesisId, setThesisId] = useState('')
  const [state, setState] = useState(null)
  const [history, setHistory] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setError('')
    setState(null)
    setHistory(null)
    if (!thesisId.trim()) {
      setError('Enter a thesisId.')
      return
    }
    setLoading(true)
    try {
      const [s, h] = await Promise.all([
        api(`/api/v1/theses/${encodeURIComponent(thesisId.trim())}`, token),
        api(`/api/v1/theses/${encodeURIComponent(thesisId.trim())}/history`, token),
      ])
      if (s.status >= 400) {
        setError(s.data?.error || `Thesis request failed (${s.status}).`)
      } else {
        setState(s.data)
      }
      if (h.status >= 400) {
        setError((e) => e || (h.data?.error || `History request failed (${h.status}).`))
      } else {
        setHistory(h.data)
      }
    } catch (e) {
      setError('Network error: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  const historyArr = Array.isArray(history) ? history : history?.history || []

  return (
    <div className="page">
      <h2>Thesis</h2>
      <p className="muted">
        Inspect the current state of a thesis record and its transaction history
        on the ledger.
      </p>
      <div className="row">
        <input
          type="text"
          placeholder="thesisId (e.g. t-0001)"
          value={thesisId}
          onChange={(e) => setThesisId(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && load()}
        />
        <button onClick={load} disabled={loading}>
          {loading ? 'Loading…' : 'Load'}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {state && (
        <div className="card">
          <div className="badge info">current state</div>
          <pre className="mono json">{JSON.stringify(state, null, 2)}</pre>
        </div>
      )}

      {historyArr.length > 0 && (
        <div className="card">
          <div className="badge info">transaction history</div>
          <ul className="timeline">
            {historyArr.map((tx, i) => (
              <li key={tx.txId || i}>
                <span className="txid mono">{tx.txId}</span>
                <span className="muted">
                  {tx.timestamp ? new Date(Number(tx.timestamp) * 1000).toLocaleString() : ''}
                </span>
                {tx.isDelete && <span className="badge warn">delete</span>}
                {tx.value && (
                  <pre className="mono json small">{JSON.stringify(tx.value, null, 2)}</pre>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [tab, setTab] = useState('proof')
  const [token, setToken] = useState(getToken())

  return (
    <div className="app">
      <header>
        <h1>vHSM Audit</h1>
        <nav>
          <button className={tab === 'proof' ? 'active' : ''} onClick={() => setTab('proof')}>
            Verify a signature
          </button>
          <button className={tab === 'thesis' ? 'active' : ''} onClick={() => setTab('thesis')}>
            Thesis
          </button>
        </nav>
        <TokenBar token={token} setToken={setToken} />
      </header>
      <main>
        {tab === 'proof' ? <ProofPage token={token} /> : <HistoryPage token={token} />}
      </main>
      <footer className="muted">
        Read-only interface. All data is fetched from the vHSM REST API.
      </footer>
    </div>
  )
}
