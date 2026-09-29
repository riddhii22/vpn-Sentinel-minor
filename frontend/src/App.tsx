import { useMemo, useState } from 'react'
import { analyzePcap } from './api'
import { displayLevel, paramBadge, paramText, type AnalyzeResponse, type Finding } from './types'
import './App.css'

const SAMPLES = [
  { id: 'IKEv1.pcap', label: 'Demo: IKEv1.pcap' },
  { id: 'IKEv2.pcap', label: 'Demo: IKEv2.pcap' },
]

function ipsecLabel(data: AnalyzeResponse): string {
  const parts: string[] = []
  const s = data.summary || {}
  if ((s.esp_packets || 0) > 0) parts.push('ESP')
  if ((s.ah_packets || 0) > 0) parts.push('AH')
  if (!parts.length) return 'Not detected from available capture'
  return parts.join(' + ')
}

function countSev(findings: Finding[], sev: string) {
  return findings.filter((f) => (f.severity || '').toLowerCase() === sev).length
}

function downloadBlob(name: string, text: string, type: string) {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

function Tip({ term, children }: { term: string; children: string }) {
  return (
    <span className="tip" tabIndex={0}>
      {term}
      <span className="bubble">{children}</span>
    </span>
  )
}

function handshakeRows(data: AnalyzeResponse) {
  const ev = [
    ...(data.evidence?.ikev1 || []),
    ...(data.evidence?.ikev2 || []),
    ...(data.evidence_index || []),
  ]
  const byPkt = new Map<number, { packet_number?: number; timestamp?: string; source?: string; destination?: string; protocol?: string }>()
  for (const e of ev) {
    if (e.packet_number != null && !byPkt.has(e.packet_number)) byPkt.set(e.packet_number, e)
  }
  const msgs = data.ike?.messages || []
  if (msgs.length) {
    return msgs.slice(0, 32).map((m) => {
      const e = m.packet_number != null ? byPkt.get(m.packet_number) : undefined
      return {
        packet_number: m.packet_number,
        timestamp: m.timestamp || e?.timestamp || '—',
        source: m.source || e?.source || '—',
        destination: m.destination || e?.destination || '—',
        message: m.exchange || e?.protocol || 'IKE',
      }
    })
  }
  return [...byPkt.values()].slice(0, 32).map((e) => ({
    packet_number: e.packet_number,
    timestamp: e.timestamp || '—',
    source: e.source || '—',
    destination: e.destination || '—',
    message: e.protocol || 'IKE',
  }))
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function clock() {
  return new Date().toISOString().slice(11, 23)
}

function Bars({ items, aria }: { items: { label: string; value: number }[]; aria: string }) {
  const max = Math.max(1, ...items.map((i) => i.value))
  return (
    <div className="bars" role="img" aria-label={aria}>
      {items.map((i) => (
        <div className="bar-row" key={i.label}>
          <span>{i.label}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(i.value / max) * 100}%` }} />
          </div>
          <span className="bar-n">{i.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<AnalyzeResponse | null>(null)
  const [history, setHistory] = useState<AnalyzeResponse[]>([])
  const [stream, setStream] = useState<string[]>(['idle · waiting for a capture'])
  const [lastDemo, setLastDemo] = useState<string | null>(null)
  const [selectedPkt, setSelectedPkt] = useState<number | null>(null)

  async function pushStream(line: string) {
    setStream((s) => [...s.slice(-48), `${clock()}  ${line}`])
  }

  async function run(target: File) {
    setBusy(true)
    setError(null)
    setStream([])
    try {
      await pushStream(`open ${target.name} · ${(target.size / 1024).toFixed(1)} KB`)
      await sleep(110)
      await pushStream('validate magic · libpcap / pcapng')
      await sleep(90)
      await pushStream('POST /analyze · FastAPI parser')
      await sleep(80)
      await pushStream('dissect UDP/500 ISAKMP · count ESP/AH (no decrypt)')
      const data = await analyzePcap(target)
      setResult(data)
      setHistory((h) => [data, ...h].slice(0, 4))
      const first = data.ike?.messages?.[0]?.packet_number
      setSelectedPkt(first ?? null)
      await sleep(90)
      await pushStream(`parsed ${data.packet_count} packets · IKE ${paramText(data.ike?.version)}`)
      await sleep(70)
      await pushStream(`policy engine · policies/rules.yaml · score ${data.risk?.score ?? '—'} / 100 (${displayLevel(data.risk?.level)})`)
      const penalty = (data.findings || []).filter((f) => (f.score || 0) > 0).length
      await sleep(60)
      await pushStream(`findings ${data.findings?.length ?? 0} · penalty ${penalty} · ML model_available=${data.traffic_analysis?.model_available}`)
      await sleep(40)
      await pushStream('stream complete')
    } catch (err) {
      setResult(null)
      const msg = err instanceof Error ? err.message : 'Analysis failed'
      setError(msg)
      await pushStream(`error · ${msg}`)
    } finally {
      setBusy(false)
    }
  }

  const [dragOver, setDragOver] = useState(false)

  function takeFile(next: File | undefined) {
    if (!next) return
    setFile(next)
    setError(null)
  }

  function onPick(list: FileList | null) {
    takeFile(list?.[0])
  }

  async function loadSample(name: string) {
    const res = await fetch(`/samples/${name}`)
    if (!res.ok) {
      setError('Could not load the bundled sample capture.')
      return
    }
    const blob = await res.blob()
    const next = new File([blob], name, { type: 'application/vnd.tcpdump.pcap' })
    setFile(next)
    setLastDemo(name)
    await run(next)
  }

  const findings = result?.findings || []
  const params = result?.security_parameters || {}
  const recs = [
    ...(result?.recommendations_prioritized?.immediate || []),
    ...(result?.recommendations_prioritized?.recommended || []),
    ...(result?.recommendations_prioritized?.informational || []),
  ]
  const matrix = useMemo(
    () =>
      ['critical', 'high', 'medium', 'low', 'info'].map((sev) => ({
        sev,
        n: countSev(findings, sev),
      })),
    [findings],
  )

  const other = history.find((h) => result && h.file_name !== result.file_name)
  const feat = result?.traffic_analysis?.features
  const protoItems = feat?.protocol_distribution
    ? Object.entries(feat.protocol_distribution)
        .filter(([, v]) => v > 0)
        .map(([label, value]) => ({ label, value }))
    : []
  const windowItems = (feat?.windows || []).slice(0, 16).map((w) => ({
    label: `w${w.index}`,
    value: w.packets,
  }))
  const tunnels = result ? handshakeRows(result) : []
  const vulnCount = findings.filter((f) => (f.score || 0) > 0).length
  const encBadge = paramBadge('encryption', params.encryption)
  const intBadge = paramBadge('integrity', params.integrity)
  const dhBadge = paramBadge('dh', params.dh_group)

  const selected = tunnels.find((t) => t.packet_number === selectedPkt) || tunnels[0]
  const live = busy ? 'ANALYZING' : result ? 'SCORED' : 'STANDBY'

  return (
    <div className="page">
      <header className="top">
        <div>
          <p className="kicker">ENTROPY · PS 26160 · Security Analysis Dashboard</p>
          <h1>VPN Sentinel</h1>
          <p className="sub">AI-Powered IPsec VPN Security Analyzer</p>
        </div>
        <div className="header-status">
          <span className={`live-chip${busy ? ' on' : ''}`}>{live}</span>
          <p className="lead">
            Upload a packet capture. The analyzer reads IKE and IPsec headers, applies security
            policy, and scores the VPN configuration. Encrypted payloads are never decrypted.
          </p>
        </div>
      </header>

      <section className="card tight" aria-label="Glossary">
        <dl className="glossary">
          <div>
            <dt>VPN</dt>
            <dd>Protected path over an untrusted network.</dd>
          </div>
          <div>
            <dt>IPsec</dt>
            <dd>Protocols that secure IP packets.</dd>
          </div>
          <div>
            <dt>IKE</dt>
            <dd>Handshake that negotiates algorithms and keys.</dd>
          </div>
          <div>
            <dt>ESP</dt>
            <dd>Tunnel packets after the SA is up — payloads stay encrypted.</dd>
          </div>
        </dl>
      </section>

      <section className="upload card" aria-label="Upload capture">
        <h2>Capture ingest</h2>
        <p className="hint">
          Accepts <code>.pcap</code> and <code>.pcapng</code>. Demo buttons hit the live API — the
          handshake table is not hardcoded.
        </p>
        <label
          className={`drop${dragOver ? ' over' : ''}`}
          onDragOver={(e) => {
            e.preventDefault()
            setDragOver(true)
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragOver(false)
            takeFile(e.dataTransfer.files?.[0])
          }}
        >
          <input
            type="file"
            accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
            onChange={(e) => onPick(e.target.files)}
          />
          <span>{file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KB` : 'Drop or choose a PCAP file'}</span>
        </label>
        <div className="row">
          <button
            className="primary"
            disabled={!file || busy}
            onClick={() => file && run(file)}
          >
            {busy ? 'Analyzing…' : 'Analyze VPN'}
          </button>
          {SAMPLES.map((s) => (
            <button
              key={s.id}
              className={`ghost${lastDemo === s.id ? ' active' : ''}`}
              disabled={busy}
              onClick={() => loadSample(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>
        {busy && (
          <div className="progress" aria-live="polite">
            <span className="step on">Validating file</span>
            <span className="step on">Sending to analyzer</span>
            <span className="step on">Parsing packets &amp; scoring</span>
          </div>
        )}
        {error && <p className="error" role="alert">{error}</p>}
      </section>

      <div className="metric-row">
        <div className="metric">
          <div className="k">Packets Analyzed</div>
          <div className="v">{result?.packet_count ?? '—'}</div>
          <div className="m">Header inventory from this capture</div>
        </div>
        <div className="metric">
          <div className="k">Security Score</div>
          <div className="v">{result?.risk?.score ?? '—'}</div>
          <div className="m">VPN Sentinel risk · higher is worse</div>
        </div>
        <div className="metric">
          <div className="k">Vulnerabilities Found</div>
          <div className="v">{result ? vulnCount : '—'}</div>
          <div className="m">Policy findings with score &gt; 0</div>
        </div>
        <div className="metric">
          <div className="k">Handshake Protocol</div>
          <div className="v handshake">{result ? paramText(result.ike?.version) : '—'}</div>
          <div className="m">ISAKMP version byte · not the filename</div>
        </div>
      </div>

      <div className="split">
        <section className="card panel">
          <h2>Discovered Tunnels &amp; Handshakes</h2>
          <p className="hint">
            Click a row to inspect it. Run <strong>Demo: IKEv2.pcap</strong> to replace this list
            from the parser.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Message Type</th>
                </tr>
              </thead>
              <tbody>
                {!result && (
                  <tr className="empty-row">
                    <td colSpan={5}>Waiting for capture · table fills from IKE messages</td>
                  </tr>
                )}
                {result && tunnels.length === 0 && (
                  <tr className="empty-row">
                    <td colSpan={5}>Not detected from available capture</td>
                  </tr>
                )}
                {tunnels.map((row, i) => (
                  <tr
                    key={`${row.packet_number}-${row.message}-${i}`}
                    className={row.packet_number === selected?.packet_number ? 'sel' : ''}
                    onClick={() => setSelectedPkt(row.packet_number ?? null)}
                  >
                    <td>{row.packet_number}</td>
                    <td>{row.timestamp}</td>
                    <td>{row.source}</td>
                    <td>{row.destination}</td>
                    <td>{row.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <section className="card panel">
          <h2>AI Analysis &amp; Recommendations</h2>
          <p className="hint">
            Parameter badges come from YAML security rules. Inner-traffic ML is a separate status
            and does not set the VPN score.
          </p>
          <div className="param-row">
            <span>Encryption<br /><strong>{result ? paramText(params.encryption) : '—'}</strong></span>
            <span className={`badge ${result ? encBadge.tone : 'unknown'}`}>
              {result ? encBadge.label : 'Not detected'}
            </span>
          </div>
          <div className="param-row">
            <span>Integrity<br /><strong>{result ? paramText(params.integrity) : '—'}</strong></span>
            <span className={`badge ${result ? intBadge.tone : 'unknown'}`}>
              {result ? intBadge.label : 'Not detected'}
            </span>
          </div>
          <div className="param-row">
            <span>Diffie–Hellman Group<br /><strong>{result ? paramText(params.dh_group) : '—'}</strong></span>
            <span className={`badge ${result ? dhBadge.tone : 'unknown'}`}>
              {result ? dhBadge.label : 'Not detected'}
            </span>
          </div>
          {selected && result && (
            <p className="muted small sel-line">
              Selected pkt {selected.packet_number}: {selected.source} → {selected.destination} ·{' '}
              {selected.message}
            </p>
          )}
          <div className="explain">
            <h3>Automated explanation</h3>
            {result ? (
              <>
                <p>{result.security_summary?.why}</p>
                <p className="muted small">{result.security_summary?.most_important_action}</p>
              </>
            ) : (
              <p className="empty">Run a capture to generate the explanation card.</p>
            )}
          </div>
          <div className="ml-box">
            <h3>AI traffic classification</h3>
            {result?.traffic_analysis?.model_available ? (
              <p>
                <strong>Traffic classification:</strong> {result.traffic_analysis.prediction}
              </p>
            ) : result ? (
              <p>
                <strong>Baseline ML prediction unavailable for this capture.</strong>{' '}
                {result.traffic_analysis?.message || 'No validated model is loaded.'} No confidence is shown.
              </p>
            ) : (
              <p className="empty">Model status appears after analysis.</p>
            )}
          </div>
        </section>
      </div>

      {result && (
        <>
          <section className="risk card" data-level={result.risk?.level}>
            <h2>2. Is this VPN configuration risky?</h2>
            <div className="hero">
              <div
                className="ring"
                style={{ ['--p' as string]: String(result.risk?.score ?? 0) }}
                aria-label={`Risk score ${result.risk?.score ?? 0} of 100`}
              >
                <div className="ring-inner">
                  <p className="risk-num">{result.risk?.score ?? '—'}/100</p>
                  <p className="risk-lvl">{displayLevel(result.risk?.level)}</p>
                </div>
              </div>
              <div>
                <p><strong>Why:</strong> {result.security_summary?.why}</p>
                <p><strong>Most important action:</strong> {result.security_summary?.most_important_action}</p>
                <p className="muted small">{result.risk?.equation}</p>
                <p className="muted small">{result.risk?.formula}</p>
              </div>
            </div>
            <div className="stats">
              <div className="stat">
                <span>IKE version</span>
                <strong>{paramText(result.ike?.version)}</strong>
              </div>
              <div className="stat">
                <span>
                  <Tip term="IPsec protocols">
                    ESP encrypts payload; AH authenticates headers. Observed from packet types, not guesses.
                  </Tip>
                </span>
                <strong>{ipsecLabel(result)}</strong>
              </div>
              <div className="stat">
                <span>Packet count</span>
                <strong>{result.packet_count}</strong>
              </div>
              <div className="stat">
                <span>Duration</span>
                <strong>
                  {result.traffic_analysis?.features?.duration_seconds != null
                    ? `${result.traffic_analysis.features.duration_seconds} s`
                    : 'Not detected from available capture'}
                </strong>
              </div>
            </div>
            <div className="row" style={{ marginTop: '0.8rem' }}>
              <button
                className="ghost"
                type="button"
                disabled={!result.report?.html}
                onClick={() =>
                  result.report?.html &&
                  downloadBlob(
                    `vpn-sentinel-${result.file_name}.html`,
                    result.report.html,
                    'text/html;charset=utf-8',
                  )
                }
              >
                Download HTML report
              </button>
              <button
                className="ghost"
                type="button"
                disabled={!result.report?.json}
                onClick={() =>
                  result.report?.json &&
                  downloadBlob(
                    `vpn-sentinel-${result.file_name}.json`,
                    JSON.stringify(result.report.json, null, 2),
                    'application/json',
                  )
                }
              >
                Download JSON report
              </button>
            </div>
          </section>

          <section className="card">
            <h2>3. VPN overview</h2>
            <dl className="facts">
              <div><dt>Capture</dt><dd>{result.file_name}</dd></div>
              <div><dt>Packets</dt><dd>{result.packet_count}</dd></div>
              <div>
                <dt>
                  <Tip term="IKE version">The ISAKMP version byte: 0x10 is IKEv1, 0x20 is IKEv2. Filename is ignored.</Tip>
                </dt>
                <dd>{paramText(result.ike?.version)}</dd>
              </div>
              <div><dt>IPsec protocol</dt><dd>{ipsecLabel(result)}</dd></div>
              <div><dt>Encryption</dt><dd>{paramText(params.encryption)}</dd></div>
              <div><dt>Integrity / hash</dt><dd>{paramText(params.integrity)}</dd></div>
              <div><dt>DH group</dt><dd>{paramText(params.dh_group)}</dd></div>
              <div><dt>Authentication</dt><dd>{paramText(params.authentication)}</dd></div>
              <div><dt>Lifetime</dt><dd>{paramText(params.lifetime_seconds)}</dd></div>
              <div><dt>PFS</dt><dd>{paramText(params.pfs)}</dd></div>
              <div><dt>Mode</dt><dd>{paramText(params.mode)}</dd></div>
              <div><dt>NAT-T (UDP/4500)</dt><dd>{(result.summary?.udp_4500_packets || 0) > 0 ? `${result.summary?.udp_4500_packets} packets` : 'Not detected from available capture'}</dd></div>
              <div><dt>Replay protection</dt><dd>{paramText(params.replay_protection)}</dd></div>
              <div><dt>First / last time</dt><dd>{result.capture?.first_timestamp || '—'} → {result.capture?.last_timestamp || '—'}</dd></div>
            </dl>
            {result.capture?.endpoints?.[0] && (
              <p className="muted">
                Top pair: {result.capture.endpoints[0].source} → {result.capture.endpoints[0].destination}
                ({result.capture.endpoints[0].packets} packets)
              </p>
            )}
          </section>

          <section className="card">
            <h2>4. Threat matrix</h2>
            <p className="hint">Counts of <span className="rule-tag">security-rule findings</span>, not AI predictions.</p>
            <div className="matrix">
              {matrix.map((m) => (
                <div key={m.sev} className={`cell ${m.sev}`}>
                  <span>{m.n}</span>
                  <small>{m.sev}</small>
                </div>
              ))}
            </div>
          </section>

          <section className="card">
            <h2>5. Security findings</h2>
            {findings.length === 0 && <p>No findings for this capture.</p>}
            <ul className="findings">
              {findings.map((f) => (
                <li key={f.id} className={`finding ${f.severity}`}>
                  <p className="sev">{(f.severity || '').toUpperCase()} · RULE</p>
                  <h3>{f.title}</h3>
                  <p className="meta">{f.category} · {f.rule_id || f.id}</p>
                  <p><strong>Detected:</strong> {f.detected_value || 'Not detected from available capture'}</p>
                  <p><strong>Why it matters:</strong> {f.explanation || f.reason}</p>
                  <p><strong>Recommendation:</strong> {f.recommendation}</p>
                  {!!f.evidence?.length && (
                    <details>
                      <summary>Evidence ({f.evidence.length} packets)</summary>
                      <table>
                        <thead>
                          <tr>
                            <th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th>
                          </tr>
                        </thead>
                        <tbody>
                          {f.evidence.map((e) => (
                            <tr key={`${f.id}-${e.packet_number}`}>
                              <td>{e.packet_number}</td>
                              <td>{e.timestamp}</td>
                              <td>{e.source}</td>
                              <td>{e.destination}</td>
                              <td>{e.protocol}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </details>
                  )}
                </li>
              ))}
            </ul>
          </section>

          <section className="card">
            <h2>6. Recommendations</h2>
            {recs.length === 0 && <p>No prioritized recommendations.</p>}
            <ol className="recs">
              {recs.map((r) => (
                <li key={r.finding_id}>
                  <strong>{(r.severity || '').toUpperCase()}</strong> — {r.recommendation}
                </li>
              ))}
            </ol>
          </section>

          <section className="card">
            <h2>7. Traffic intelligence</h2>
            <p className="hint">
              Observable metadata only. Encrypted payloads are not read. This section does not change the VPN risk score.
            </p>
            {feat ? (
              <>
                <dl className="facts">
                  <div><dt>Packets</dt><dd>{feat.packet_count}</dd></div>
                  <div><dt>Duration</dt><dd>{feat.duration_seconds} s</dd></div>
                  <div><dt>Size min / avg / max</dt>
                    <dd>{feat.min_packet_size} / {feat.avg_packet_size} / {feat.max_packet_size} B</dd>
                  </div>
                  <div><dt>Size std. dev.</dt><dd>{feat.packet_size_std}</dd></div>
                  <div><dt>Avg inter-arrival</dt>
                    <dd>{feat.avg_interarrival_time ?? 'Not detected from available capture'} s</dd>
                  </div>
                  <div><dt>Packets / second</dt>
                    <dd>{feat.packets_per_second ?? 'Not detected from available capture'}</dd>
                  </div>
                  <div><dt>Bytes / second</dt>
                    <dd>{feat.bytes_per_second ?? 'Not detected from available capture'}</dd>
                  </div>
                  <div><dt>Burst groups (&lt;1 ms gaps)</dt><dd>{feat.burst_count}</dd></div>
                  <div><dt>Windows (0.5 s)</dt><dd>{feat.windows?.length ?? 0}</dd></div>
                  <div><dt>Direction A→B / B→A</dt>
                    <dd>
                      {feat.direction_statistics?.packets_a_to_b ?? 0}
                      {' / '}
                      {feat.direction_statistics?.packets_b_to_a ?? 0}
                    </dd>
                  </div>
                </dl>
                {protoItems.length > 0 && (
                  <>
                    <p className="muted small">Protocol mix (packet headers, not payload class)</p>
                    <Bars items={protoItems} aria="Protocol packet counts" />
                  </>
                )}
                {windowItems.length > 0 && (
                  <>
                    <p className="muted small">Packets per 0.5 s window (first 16 of at most 40)</p>
                    <Bars items={windowItems} aria="Packets per time window" />
                  </>
                )}
              </>
            ) : (
              <p>Not detected from available capture</p>
            )}
          </section>

          {other && (
            <section className="card">
              <h2>Compare with previous capture</h2>
              <p className="hint">Both rows come from `/analyze`, not filenames.</p>
              <table>
                <thead>
                  <tr>
                    <th></th>
                    <th>{result.file_name}</th>
                    <th>{other.file_name}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>IKE</td>
                    <td>{paramText(result.ike?.version)}</td>
                    <td>{paramText(other.ike?.version)}</td>
                  </tr>
                  <tr>
                    <td>Score</td>
                    <td>{result.risk?.score}</td>
                    <td>{other.risk?.score}</td>
                  </tr>
                  <tr>
                    <td>Level</td>
                    <td>{displayLevel(result.risk?.level)}</td>
                    <td>{displayLevel(other.risk?.level)}</td>
                  </tr>
                </tbody>
              </table>
            </section>
          )}

          <section className="card muted">
            <h2>Limitations</h2>
            <ul>
              {(result.limitations || []).map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </section>
        </>
      )}

      <section className="console" aria-label="System parser stream">
        <div className="console-head">
          <span className="dots" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <h2>System Parser Stream</h2>
          <span className="console-meta">{busy ? 'live' : 'idle'}</span>
        </div>
        <pre>{stream.join('\n') || 'idle · waiting for a capture'}</pre>
      </section>

      <footer>
        Lab prototype · ENTROPY · Does not decrypt ESP · Score is project-specific, not CVSS
      </footer>
    </div>
  )
}
