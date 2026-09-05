import React, { useState, useEffect, useRef, useCallback } from 'react'

const TOKEN_KEY = 'vhsm_jwt'
function getToken() { return localStorage.getItem(TOKEN_KEY) || '' }

async function api(path, token, opts = {}) {
  const headers = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (opts.body) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, { ...opts, headers: { ...headers, ...(opts.headers||{}) } })
  const text = await res.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { data = text }
  return { status: res.status, data, ok: res.ok }
}

// ---------- helpers ----------
function tsFmt(s) {
  if (!s) return '—'
  const d = new Date(Number(s) * 1000)
  if (isNaN(d.getTime())) return String(s)
  return d.toLocaleString()
}
function short(s, n=12) {
  if (!s) return '—'
  return s.length > n ? s.slice(0,n) + '…' : s
}

// ---------- Token bar ----------
function TokenBar({ token, setToken }) {
  const [value, setValue] = useState(token)
  useEffect(()=>setValue(token),[token])
  return (
    <div className="tokenbar">
      <span className="tlabel">◉ JWT AUTH</span>
      <input type="text" placeholder="paste JWT from POST /api/v1/login" value={value} onChange={e=>setValue(e.target.value)} />
      <button className="btn btn-glow" onClick={()=>{ localStorage.setItem(TOKEN_KEY, value.trim()); setToken(value.trim())}}>Save</button>
      {token && <span className="ok">● connected</span>}
      {!token && <span className="warn">○ disconnected — login required</span>}
    </div>
  )
}

// ---------- Loading overlay (automatic peer join etc) ----------
function DeployOverlay({ job, onClose, onDone }) {
  const pct = job?.progress ?? 0
  const done = job?.status === 'success'
  const failed = job?.status === 'failed'
  return (
    <div className="overlay">
      <div className="overlay-card">
        <div className="overlay-head">
          <div className="pulse" />
          <h3>{done ? 'NETWORK READY' : failed ? 'DEPLOYMENT FAILED' : 'SYNCHRONIZING FABRIC NETWORK'}</h3>
          <span className="mono small">{pct}%</span>
        </div>
        <div className="progress-track"><div className="progress-fill" style={{width: pct+'%'}} /></div>
        <p className="muted small">Peers are automatically joining channels, chaincode is being approved and committed. Do not close this window.</p>
        <div className="steps">
          {(job?.steps||[]).map((s,i)=>(
            <div key={i} className={`step ${s.status}`}>
              <span className="step-dot">{s.status==='done'?'✓':s.status==='running'?'◐':'○'}</span>
              <span className="step-name">{s.name}</span>
              <span className={`step-badge ${s.status}`}>{s.status}</span>
              {s.log && <div className="step-log mono">{s.log}</div>}
            </div>
          ))}
        </div>
        {job?.error && <div className="error">{job.error}</div>}
        <div className="row" style={{justifyContent:'flex-end'}}>
          {done && <button className="btn btn-glow" onClick={()=>{onDone?.(); onClose()}}>Enter dashboard</button>}
          {failed && <button className="btn" onClick={onClose}>Close</button>}
        </div>
      </div>
    </div>
  )
}

// ---------- Dashboard ----------
function Dashboard({ token, status }) {
  if (!status) return <div className="card"><p className="muted">Loading network topology…</p></div>
  const totalPeers = status.orgs.reduce((a,o)=>a+o.peers.length,0)
  const runningPeers = status.orgs.reduce((a,o)=>a+o.peers.filter(p=>p.status==='running').length,0)
  return (
    <>
      <div className="kpi-grid">
        <div className="kpi"><div className="kpi-label">Orderer</div><div className="kpi-value">{status.orderer.host}</div><div className={`kpi-badge ${status.orderer.status}`}>{status.orderer.status}</div></div>
        <div className="kpi"><div className="kpi-label">Peers</div><div className="kpi-value">{runningPeers} / {totalPeers} <span className="muted">online</span></div><div className="kpi-sub">{status.orgs.length} org(s) · {status.channels.length} channel(s)</div></div>
        <div className="kpi"><div className="kpi-label">Ledger Height</div><div className="kpi-value">#{status.lastBlock}</div><div className="kpi-sub">{status.txCount} transactions anchored</div></div>
        <div className="kpi"><div className="kpi-label">Chaincodes</div><div className="kpi-value">{status.chaincodes.length}</div><div className="kpi-sub">{status.chaincodes.map(c=>c.name).join(', ')}</div></div>
      </div>

      <div className="grid2">
        <div className="card">
          <h3 className="card-title">Network Topology</h3>
          <div className="topo">
            <div className="topo-orderer">
              <div className="node orderer">♦ ORDERER<br/><span className="mono small">{status.orderer.host}:7050</span><br/><span className="tag">etcdraft</span></div>
            </div>
            <div className="topo-orgs">
              {status.orgs.map(org=>(
                <div key={org.name} className="org-block">
                  <div className="org-head">{org.name} <span className="mono small">{org.msp}</span> <span className="tag">{org.domain}</span></div>
                  <div className="peer-row">
                    {org.peers.map(p=>(
                      <div key={p.id} className={`node peer ${p.status}`}>
                        <span className="peer-name">{p.name}</span>
                        <span className="mono small">{p.host}:{p.port}</span>
                        <span className="tag">{p.channel || 'no channel'}</span>
                        <span className={`dot ${p.status}`} />
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="card">
          <h3 className="card-title">Channel Map</h3>
          <table className="tbl">
            <thead><tr><th>Channel</th><th>Orgs</th><th>Height</th><th>Status</th></tr></thead>
            <tbody>
              {status.channels.map(ch=>(
                <tr key={ch.name}><td className="mono">{ch.name}</td><td>{ch.orgs.join(', ')}</td><td>#{ch.blockHeight}</td><td><span className="badge ok">{ch.status}</span></td></tr>
              ))}
            </tbody>
          </table>
          <h4 className="mt">Chaincodes</h4>
          <table className="tbl">
            <thead><tr><th>Name</th><th>Channel</th><th>Version</th><th>Status</th></tr></thead>
            <tbody>
              {status.chaincodes.map(cc=>(
                <tr key={cc.name}><td className="mono">{cc.name}</td><td>{cc.channel}</td><td>{cc.version}</td><td><span className="badge info">{cc.status}</span></td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}

// ---------- Builder ----------
function Builder({ token, onDeployStart }) {
  const [ordererDomain, setOrdererDomain] = useState('university.com')
  const [orgs, setOrgs] = useState([
    { name:'misa', msp:'misaMSP', domain:'misa.university.com', peers:[{host:'peer0.misa.university.com', port:7051, externalPort:7052},{host:'peer1.misa.university.com', port:7053, externalPort:7054}], hasCli:true }
  ])
  const [channels, setChannels] = useState([{ name:'canaltest', orgs:['1'] }])
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  const addOrg = () => setOrgs([...orgs, { name:`org${orgs.length+1}`, msp:`org${orgs.length+1}MSP`, domain:`org${orgs.length+1}.${ordererDomain}`, peers:[{host:`peer0.org${orgs.length+1}.${ordererDomain}`, port:7051+orgs.length*100, externalPort:7052+orgs.length*100}], hasCli:true }])
  const addPeer = (idx) => {
    const copy = [...orgs]; const org = copy[idx]
    const pIdx = org.peers.length
    org.peers.push({ host:`peer${pIdx}.${org.domain}`, port:7051+pIdx*10, externalPort:7052+pIdx*10 })
    setOrgs(copy)
  }
  const updateOrg = (idx, field, val) => { const c=[...orgs]; c[idx][field]=val; setOrgs(c) }
  const updatePeer = (oi, pi, field, val) => { const c=[...orgs]; c[oi].peers[pi][field]=val; setOrgs(c) }

  const generate = async () => {
    setBusy(true); setMsg('')
    const payload = { ordererDomain, orgs, channels }
    const r = await api('/api/v1/fabric/network', token, { method:'POST', body: JSON.stringify(payload) })
    if (r.status>=400) setMsg(r.data?.error || `Failed (${r.status})`)
    else { setMsg('Network configuration generated. Now click Deploy to start automatic enrollment & channel join.'); }
    setBusy(false)
  }
  const deploy = async () => {
    setBusy(true)
    const r = await api('/api/v1/fabric/deploy', token, { method:'POST' })
    if (r.status>=400) { setMsg(r.data?.error || 'Deploy failed'); setBusy(false) }
    else { onDeployStart(r.data.id); setBusy(false) }
  }

  return (
    <div className="card">
      <h2 className="card-title">Blockchain Environment Builder</h2>
      <p className="muted">Replicates <code>generate-network.sh</code> + <code>enroll-network.sh</code> as a guided web wizard. All channel joins and chaincode approvals are automatic — you only watch the loading screen.</p>

      <label className="lbl">Orderer Domain</label>
      <input value={ordererDomain} onChange={e=>setOrdererDomain(e.target.value)} placeholder="university.com" />

      <h3 className="section-title">Organizations & Peers</h3>
      {orgs.map((org, oi)=>(
        <div key={oi} className="builder-org">
          <div className="row">
            <input value={org.name} onChange={e=>updateOrg(oi,'name',e.target.value)} placeholder="name (misa)" />
            <input value={org.msp} onChange={e=>updateOrg(oi,'msp',e.target.value)} placeholder="MSP (misaMSP)" />
            <input value={org.domain} onChange={e=>updateOrg(oi,'domain',e.target.value)} placeholder="domain" />
            <label className="check"><input type="checkbox" checked={org.hasCli} onChange={e=>updateOrg(oi,'hasCli',e.target.checked)} /> CLI</label>
          </div>
          {org.peers.map((p,pi)=>(
            <div key={pi} className="row peer-edit">
              <span className="mono small">{p.host}</span>
              <input value={p.host} onChange={e=>updatePeer(oi,pi,'host',e.target.value)} placeholder="peer host" />
              <input type="number" value={p.port} onChange={e=>updatePeer(oi,pi,'port',parseInt(e.target.value)||7051)} style={{width:90}} />
              <input type="number" value={p.externalPort} onChange={e=>updatePeer(oi,pi,'externalPort',parseInt(e.target.value)||7051)} style={{width:90}} />
            </div>
          ))}
          <button className="btn btn-sm" onClick={()=>addPeer(oi)}>+ Add peer</button>
        </div>
      ))}
      <button className="btn btn-sm" onClick={addOrg}>+ Add organization</button>

      <h3 className="section-title">Channels</h3>
      {channels.map((ch,ci)=>(
        <div key={ci} className="row">
          <input value={ch.name} onChange={e=>{ const c=[...channels]; c[ci].name=e.target.value; setChannels(c)}} placeholder="channel name (canaltest)" />
          <input value={ch.orgs.join(' ')} onChange={e=>{ const c=[...channels]; c[ci].orgs=e.target.value.split(' ').filter(Boolean); setChannels(c)}} placeholder="org indices (e.g. 1 2)" />
        </div>
      ))}
      <button className="btn btn-sm" onClick={()=>setChannels([...channels,{name:`channel${channels.length+1}`,orgs:['1']}])}>+ Add channel</button>

      <div className="row mt">
        <button className="btn btn-glow" onClick={generate} disabled={busy}>{busy?'Working…':'Generate network (write network.env)'}</button>
        <button className="btn btn-primary" onClick={deploy} disabled={busy}>▶ Deploy & Auto-Join (loading screen)</button>
      </div>
      {msg && <div className="info-box">{msg}</div>}
      <p className="muted small mt">Equivalent CLI: <code>./generate-network.sh → ./enroll-network.sh → docker compose up → peer channel join → chaincode install/approve/commit</code> — all automated.</p>
    </div>
  )
}

// ---------- Infrastructure (edit, no delete) ----------
function Infra({ token, status, refresh }) {
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({ name:'', host:'', channel:'' })
  const [msg, setMsg] = useState('')
  if (!status) return null
  const openEdit = (peer) => { setEditing(peer.id); setForm({ name:peer.name, host:peer.host, channel:peer.channel||'' }); setMsg('') }
  const save = async () => {
    const r = await api(`/api/v1/fabric/peers/${editing}`, token, { method:'PUT', body: JSON.stringify(form) })
    if (r.status>=400) setMsg(r.data?.error || 'Update failed')
    else { setMsg('Peer updated. Channel assignment will propagate after next deploy.'); setEditing(null); refresh() }
  }
  return (
    <div className="card">
      <h3 className="card-title">Infrastructure — Peers & Orderers</h3>
      <p className="muted">Edit peers (rename, re-assign channel). No removal allowed — peers are immutable infrastructure.</p>
      {status.orgs.map(org=>(
        <div key={org.name} className="infra-org">
          <h4>{org.name} <span className="mono small">{org.msp} · {org.domain}</span></h4>
          <div className="peer-grid">
            {org.peers.map(p=>(
              <div key={p.id} className="peer-card">
                <div className="peer-card-head">
                  <span className="peer-id mono">{p.id}</span>
                  <span className={`dot ${p.status}`} title={p.status} />
                </div>
                <div className="mono small">{p.host}:{p.port} → :{p.externalPort}</div>
                <div><span className="tag">{p.channel||'unassigned'}</span> {p.anchor && <span className="tag anchor">anchor</span>}</div>
                <button className="btn btn-sm" onClick={()=>openEdit(p)}>✎ Edit</button>
              </div>
            ))}
          </div>
        </div>
      ))}
      {editing && (
        <div className="modal">
          <div className="modal-card">
            <h4>Edit Peer — {editing}</h4>
            <label className="lbl">Display name</label>
            <input value={form.name} onChange={e=>setForm({...form,name:e.target.value})} />
            <label className="lbl">Hostname</label>
            <input value={form.host} onChange={e=>setForm({...form,host:e.target.value})} />
            <label className="lbl">Channel (canal)</label>
            <select value={form.channel} onChange={e=>setForm({...form,channel:e.target.value})}>
              <option value="">— unassigned —</option>
              {status.channels.map(c=> <option key={c.name} value={c.name}>{c.name}</option>)}
            </select>
            <div className="row">
              <button className="btn btn-glow" onClick={save}>Save changes</button>
              <button className="btn" onClick={()=>setEditing(null)}>Cancel</button>
            </div>
            {msg && <div className="info-box">{msg}</div>}
            <p className="muted small">Renaming updates peer identity; changing channel re-assigns the org to that channel's consortium (no peer deletion).</p>
          </div>
        </div>
      )}
      {msg && !editing && <div className="info-box">{msg}</div>}
      <div className="card muted small mt" style={{background:'rgba(14,165,233,0.06)'}}>
        ℹ Deletion is disabled by policy. To decommission a peer, edit its config and redeploy the network.
      </div>
    </div>
  )
}

// ---------- Live Transactions ----------
function LiveTx({ token }) {
  const [txs, setTxs] = useState([])
  const [filter, setFilter] = useState('')
  const [channel, setChannel] = useState('')
  const [selected, setSelected] = useState(null)
  const [live, setLive] = useState(true)

  const fetchTxs = useCallback(async ()=>{
    const q = new URLSearchParams({ limit: '50', ...(channel?{channel}:{}) })
    const r = await api(`/api/v1/fabric/transactions?${q}`, token)
    if (r.ok) setTxs(r.data.transactions || [])
  }, [token, channel])

  useEffect(()=>{ fetchTxs(); },[fetchTxs])
  useEffect(()=>{
    if (!live) return
    const id = setInterval(fetchTxs, 4000)
    return ()=>clearInterval(id)
  },[live, fetchTxs])

  // SSE attempt (non-blocking)
  useEffect(()=>{
    if (!token || !live) return
    let es
    try {
      es = new EventSource(`/api/v1/fabric/transactions/stream`)
      // Note: EventSource doesn't support auth header; fallback to polling only
      es.onerror = ()=> es.close()
    } catch {}
    return ()=> es?.close()
  },[token,live])

  const filtered = txs.filter(t=>{
    if (!filter) return true
    const hay = `${t.txId} ${t.function} ${t.channel} ${t.submitter}`.toLowerCase()
    return hay.includes(filter.toLowerCase())
  })

  return (
    <div className="card">
      <div className="row" style={{justifyContent:'space-between'}}>
        <h3 className="card-title">Live Transactions <span className={`live-dot ${live?'on':''}`}>● {live?'LIVE':''}</span></h3>
        <div className="row">
          <input placeholder="search txId / function / submitter" value={filter} onChange={e=>setFilter(e.target.value)} style={{width:280}} />
          <select value={channel} onChange={e=>setChannel(e.target.value)}>
            <option value="">all channels</option>
            <option value="canaltest">canaltest</option>
            <option value="signaturechannel">signaturechannel</option>
            <option value="mychannel">mychannel</option>
          </select>
          <button className={`btn btn-sm ${live?'btn-glow':''}`} onClick={()=>setLive(!live)}>{live?'⏸ Pause':'▶ Live'}</button>
          <button className="btn btn-sm" onClick={fetchTxs}>↻ Refresh</button>
        </div>
      </div>
      <div className="tbl-wrap">
        <table className="tbl">
          <thead><tr><th>Time</th><th>TxID</th><th>Channel</th><th>Chaincode · Function</th><th>Submitter</th><th>Block</th><th>Status</th></tr></thead>
          <tbody>
            {filtered.map(t=>(
              <tr key={t.txId} onClick={()=>setSelected(t)} style={{cursor:'pointer'}}>
                <td className="mono small">{tsFmt(t.timestamp)}</td>
                <td className="mono small">{short(t.txId,16)}</td>
                <td><span className="tag">{t.channel}</span></td>
                <td><span className="mono">{t.chaincode}</span> · <span className="tag">{t.function}</span></td>
                <td className="mono small">{short(t.submitter,22)}</td>
                <td>#{t.blockNumber}</td>
                <td><span className={`badge ${t.status==='VALID'?'ok':'warn'}`}>{t.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && (
        <div className="drawer">
          <div className="drawer-head">
            <h4 className="mono">Transaction Detail — {short(selected.txId,24)}</h4>
            <button className="btn btn-sm" onClick={()=>setSelected(null)}>✕ Close</button>
          </div>
          <div className="kv-grid">
            <div><span className="muted">TxID</span><span className="mono">{selected.txId}</span></div>
            <div><span className="muted">Channel</span><span>{selected.channel}</span></div>
            <div><span className="muted">Chaincode</span><span className="mono">{selected.chaincode}</span></div>
            <div><span className="muted">Function</span><span className="tag">{selected.function}</span></div>
            <div><span className="muted">Block</span><span>#{selected.blockNumber}</span></div>
            <div><span className="muted">Type</span><span>{selected.type}</span></div>
            <div><span className="muted">Timestamp</span><span>{tsFmt(selected.timestamp)} ({selected.timestamp})</span></div>
            <div><span className="muted">Submitter / MSP</span><span className="mono">{selected.submitter} · {selected.submitterMSP}</span></div>
            <div><span className="muted">Endorser</span><span className="mono">{selected.endorser}</span></div>
            <div><span className="muted">Payload hash</span><span className="mono">{selected.payloadHash}</span></div>
            <div><span className="muted">Args</span><pre className="mono json small">{selected.args}</pre></div>
            <div><span className="muted">Validation</span><span className={`badge ${selected.status==='VALID'?'ok':'warn'}`}>{selected.status} — {selected.status==='VALID'?'endorsement & MVCC passed':'rejected'}</span></div>
          </div>
          <p className="muted small">Full read/write set and endorsement policy details are available via peer CLI: <code>peer channel getinfo -c {selected.channel}</code> and <code>peer transaction get -c {selected.channel} --txid {selected.txId}</code>.</p>
        </div>
      )}
      <p className="muted small">Polling every 4s. Each row shows the maximum available metadata: transaction hash, endorsement, block inclusion proof, and submitter identity.</p>
    </div>
  )
}

// ---------- Audit ----------
function AuditPanel({ token }) {
  const [events, setEvents] = useState([])
  const [verifying, setVerifying] = useState(false)
  const [last, setLast] = useState(null)

  const load = useCallback(async()=>{
    const r = await api('/api/v1/fabric/audit', token)
    if (r.ok) setEvents(r.data.events || r.data || [])
  },[token])
  useEffect(()=>{ load(); const id=setInterval(load, 8000); return ()=>clearInterval(id)},[load])

  const verify = async ()=>{
    setVerifying(true)
    const r = await api('/api/v1/fabric/audit/verify', token, { method:'POST' })
    setLast(r.data)
    await load()
    setVerifying(false)
  }
  const simulateTamper = async (enable)=>{
    await api('/api/v1/fabric/audit/simulate-tamper', token, { method:'POST', body: JSON.stringify({enable}) })
    await load()
  }

  const hasTamper = events.some(e=>e.status==='tamper') || last?.status==='tamper'
  const hasWarn = events.some(e=>e.status==='warning')

  return (
    <div className="card">
      <h3 className="card-title">Automatic Audit — Tamper Detection</h3>
      {hasTamper && <div className="alert tamper">🚨 TAMPER DETECTED — Audit hash-chain diverges from ledger anchor. Ledger proof invalid. Immediate review required.</div>}
      {!hasTamper && hasWarn && <div className="alert warn">⚠ Warning — anomalous block interval detected. Not yet a tamper, but flagged for review.</div>}
      {!hasTamper && !hasWarn && <div className="alert ok">✓ No tamper — audit chain and ledger anchors are consistent.</div>}

      <div className="row">
        <button className="btn btn-glow" onClick={verify} disabled={verifying}>{verifying?'Verifying…':'▶ Verify integrity now'}</button>
        <button className="btn btn-sm" onClick={()=>simulateTamper(true)}>Simulate tamper (test)</button>
        <button className="btn btn-sm" onClick={()=>simulateTamper(false)}>Clear simulation</button>
        <span className="muted small">Runs HMAC chain walk + ledger cross-check (VerifyIntegrity).</span>
      </div>

      {last && (
        <div className={`card ${last.status==='tamper'?'tamper-card': last.status==='warning'?'warn-card':''}`} style={{marginTop:12}}>
          <div className={`badge ${last.status==='tamper'?'warn': last.status==='ok'?'ok':'info'}`} style={{background: last.status==='tamper'?'rgba(239,68,68,0.2)':''}}>{last.status?.toUpperCase()}</div>
          <p><strong>{last.message}</strong></p>
          <p className="muted small">{last.details}</p>
          <p className="mono small">tail_hash: {last.tailHash} · seq: {last.seq} · {tsFmt(last.timestamp)}</p>
        </div>
      )}

      <h4 className="mt">Audit Anchor History</h4>
      <div className="timeline">
        {events.slice(0,12).map(ev=>(
          <div key={ev.id} className={`tl-item ${ev.status}`}>
            <div className="tl-dot" />
            <div>
              <span className="mono small">#{ev.seq} — {tsFmt(ev.timestamp)}</span>
              <span className={`badge ${ev.status==='tamper'?'warn':ev.status==='ok'?'ok':'info'}`} style={{marginLeft:8}}>{ev.status}</span>
              <div className="mono small" style={{wordBreak:'break-all'}}>{ev.tailHash}</div>
              <div className="muted small">{ev.message}</div>
            </div>
          </div>
        ))}
      </div>
      <p className="muted small">The C++ vhsmd daemon anchors the audit HMAC tail via <code>RecordAuditTail</code> on <code>signature_ledger</code>. This panel cross-checks the local chain against the ledger.</p>
    </div>
  )
}

// ---------- vHSM Sign ----------
function HSMPanel({ token }) {
  const [payload, setPayload] = useState('Hello vHSM — sign this thesis digest.')
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const sign = async ()=>{
    setErr(''); setRes(null); setLoading(true)
    const r = await api('/api/v1/fabric/sign', token, { method:'POST', body: JSON.stringify({payload}) })
    if (r.status>=400) setErr(r.data?.error || `Sign failed (${r.status})`)
    else setRes(r.data)
    setLoading(false)
  }
  return (
    <div className="card">
      <h3 className="card-title">vHSM Signing — Private Key in Hardware</h3>
      <p className="muted">Payload is hashed (SHA-256) and signed inside the vHSM via PKCS#11 <code>C_Sign</code>. The signature is anchored on <code>signature_ledger</code> (RecordSignature) for externally verifiable proof.</p>
      <label className="lbl">Payload to sign (any text / document digest)</label>
      <textarea value={payload} onChange={e=>setPayload(e.target.value)} rows={4} placeholder="Enter payload…" />
      <div className="row">
        <button className="btn btn-glow" onClick={sign} disabled={loading || !payload.trim()}>{loading?'Signing via HSM…':'🔐 Sign with vHSM'}</button>
        <span className="muted small">Uses key label from HSM_SIGN_LABEL (ECDSA P-256 or RSA) — auto-detected.</span>
      </div>
      {err && <div className="error">{err}</div>}
      {res && (
        <div className="card" style={{marginTop:12, borderColor:'#0ea5e9'}}>
          <div className="badge ok">✓ signed & anchored</div>
          <div className="kv-grid">
            <div><span className="muted">Algorithm</span><span>{res.algorithm}</span></div>
            <div><span className="muted">Payload hash (SHA-256)</span><span className="mono">{res.payloadHash}</span></div>
            <div><span className="muted">Signature (hex)</span><span className="mono" style={{wordBreak:'break-all'}}>{res.signature}</span></div>
            <div><span className="muted">Signature (base64)</span><span className="mono" style={{wordBreak:'break-all'}}>{res.signatureB64}</span></div>
          </div>
          <p className="muted small">Verify on ledger via <code>GET /api/v1/proof/:recordId</code> or chaincode <code>GetRecord</code>. Anchored block & txId become visible in Live Transactions.</p>
        </div>
      )}
    </div>
  )
}

// ---------- legacy verify/thesis (kept compact) ----------
function ProofPage({ token }) {
  const [recordId, setRecordId] = useState('')
  const [proof, setProof] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const verify = async () => {
    setError(''); setProof(null)
    if (!recordId.trim()) { setError('Enter a recordId.'); return }
    setLoading(true)
    const { status, data } = await api(`/api/v1/proof/${encodeURIComponent(recordId.trim())}`, token)
    if (status===404) setError('Signature record not found on the ledger.')
    else if (status>=400) setError(data?.error || `Request failed (${status}).`)
    else setProof(data)
    setLoading(false)
  }
  const anchored = proof && Number(proof.block_number) > 0
  return (
    <div className="card">
      <h3 className="card-title">Signature Proof — Ledger Verification</h3>
      <p className="muted">Look up a record anchored by the HSM on <code>signature_ledger</code>.</p>
      <div className="row"><input placeholder="recordId (e.g. sig-0001)" value={recordId} onChange={e=>setRecordId(e.target.value)} onKeyDown={e=>e.key==='Enter'&&verify()} /><button className="btn btn-glow" onClick={verify} disabled={loading}>{loading?'Verifying…':'Verify'}</button></div>
      {error && <div className="error">{error}</div>}
      {proof && (
        <div className="card" style={{marginTop:12}}>
          {anchored ? <div className="badge ok">✓ anchored in block {proof.block_number} {proof.tx_id?`(tx ${short(proof.tx_id)})`:''}</div> : <div className="badge warn">pending</div>}
          <div className="kv-grid">
            <div><span className="muted">Record ID</span><span className="mono">{proof.record_id}</span></div>
            <div><span className="muted">Key fingerprint</span><span className="mono">{proof.key_fingerprint}</span></div>
            <div><span className="muted">Payload digest</span><span className="mono" style={{wordBreak:'break-all'}}>{proof.payload_digest}</span></div>
            <div><span className="muted">Signature (b64)</span><span className="mono" style={{wordBreak:'break-all'}}>{proof.signature_b64}</span></div>
            <div><span className="muted">Tx ID</span><span className="mono">{proof.tx_id}</span></div>
            <div><span className="muted">Block</span><span>{proof.block_number}</span></div>
          </div>
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
    setError(''); setState(null); setHistory(null)
    if (!thesisId.trim()) { setError('Enter a thesisId.'); return }
    setLoading(true)
    const [s,h] = await Promise.all([
      api(`/api/v1/theses/${encodeURIComponent(thesisId.trim())}`, token),
      api(`/api/v1/theses/${encodeURIComponent(thesisId.trim())}/history`, token),
    ])
    if (s.status>=400) setError(s.data?.error || `Thesis request failed (${s.status}).`); else setState(s.data)
    if (h.status>=400) setError(e=>e|| (h.data?.error||`History failed (${h.status}).`)); else setHistory(h.data)
    setLoading(false)
  }
  const historyArr = Array.isArray(history) ? history : history?.history || []
  return (
    <div className="card">
      <h3 className="card-title">Thesis — State & History</h3>
      <div className="row"><input placeholder="thesisId (e.g. t-0001)" value={thesisId} onChange={e=>setThesisId(e.target.value)} onKeyDown={e=>e.key==='Enter'&&load()} /><button className="btn btn-glow" onClick={load} disabled={loading}>{loading?'Loading…':'Load'}</button></div>
      {error && <div className="error">{error}</div>}
      {state && <div className="card" style={{marginTop:12}}><div className="badge info">current state</div><pre className="mono json">{JSON.stringify(state,null,2)}</pre></div>}
      {historyArr.length>0 && <div className="card" style={{marginTop:12}}><div className="badge info">transaction history</div><ul className="timeline-basic">{historyArr.map((tx,i)=><li key={tx.txId||i}><span className="mono">{tx.txId}</span> <span className="muted">{tx.timestamp?tsFmt(tx.timestamp):''}</span><pre className="mono json small">{JSON.stringify(tx.value??tx,null,2)}</pre></li>)}</ul></div>}
    </div>
  )
}

// ---------- App ----------
export default function App() {
  const [tab, setTab] = useState('dashboard')
  const [token, setToken] = useState(getToken())
  const [status, setStatus] = useState(null)
  const [deployJob, setDeployJob] = useState(null)
  const [deployJobId, setDeployJobId] = useState(null)
  const pollRef = useRef(null)

  const refreshStatus = useCallback(async()=>{
    if (!token) return
    const r = await api('/api/v1/fabric/status', token)
    if (r.ok) setStatus(r.data)
  },[token])

  useEffect(()=>{ refreshStatus(); const id=setInterval(refreshStatus, 10000); return ()=>clearInterval(id)},[refreshStatus])

  const startDeployPoll = (jobId)=>{
    setDeployJobId(jobId)
    setDeployJob({ status:'running', progress:0, steps:[] })
    pollRef.current = setInterval(async()=>{
      const r = await api(`/api/v1/fabric/jobs/${jobId}`, token)
      if (r.ok) {
        setDeployJob(r.data)
        if (r.data.status==='success' || r.data.status==='failed') {
          clearInterval(pollRef.current)
          refreshStatus()
        }
      }
    }, 900)
  }
  useEffect(()=>()=>pollRef.current&&clearInterval(pollRef.current),[])

  const tabs = [
    {id:'dashboard', label:'Dashboard'},
    {id:'builder', label:'Builder'},
    {id:'infra', label:'Infrastructure'},
    {id:'tx', label:'Live Transactions'},
    {id:'audit', label:'Audit'},
    {id:'hsm', label:'vHSM Sign'},
    {id:'proof', label:'Verify'},
    {id:'thesis', label:'Thesis'},
  ]

  return (
    <div className="app">
      <div className="grid-bg" />
      <header className="header">
        <div className="brand">
          <span className="brand-mark">⬢</span>
          <div>
            <h1>vHSM Fabric Console</h1>
            <span className="muted small">Docker · Hyperledger Fabric · vHSM</span>
          </div>
          <span className="brand-tag">blue / techno</span>
        </div>
        <nav className="nav">
          {tabs.map(t=>(
            <button key={t.id} className={tab===t.id?'active':''} onClick={()=>setTab(t.id)}>{t.label}</button>
          ))}
        </nav>
        <TokenBar token={token} setToken={setToken} />
      </header>

      {deployJobId && deployJob && deployJob.status!=='success' && (
        <DeployOverlay job={deployJob} onClose={()=>setDeployJobId(null)} onDone={refreshStatus} />
      )}
      {deployJobId && deployJob?.status==='success' && (
        <DeployOverlay job={deployJob} onClose={()=>setDeployJobId(null)} onDone={refreshStatus} />
      )}

      <main>
        {!token && <div className="alert warn">🔒 Authenticate via <code>POST /api/v1/login</code> (LDAP) and paste the JWT above to enable Fabric operations.</div>}
        {tab==='dashboard' && <Dashboard token={token} status={status} />}
        {tab==='builder' && <Builder token={token} onDeployStart={startDeployPoll} />}
        {tab==='infra' && <Infra token={token} status={status} refresh={refreshStatus} />}
        {tab==='tx' && <LiveTx token={token} />}
        {tab==='audit' && <AuditPanel token={token} />}
        {tab==='hsm' && <HSMPanel token={token} />}
        {tab==='proof' && <ProofPage token={token} />}
        {tab==='thesis' && <HistoryPage token={token} />}
      </main>

      <footer className="muted small" style={{textAlign:'center', padding:'18px 0'}}>
        vHSM · Fabric lifecycle console · generate-network.sh · enroll-network.sh · approve / commit chaincode · audit tail · live ledger
      </footer>
    </div>
  )
}
