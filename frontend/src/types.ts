export type Param = {
  status?: string
  value?: string | number | null
  detail?: string
  name?: string
  unit?: string
}

export type Finding = {
  id: string
  rule_id?: string
  title: string
  severity: string
  category?: string
  detected_value?: string | null
  explanation?: string
  reason?: string
  recommendation?: string
  score?: number
  evidence?: EvidenceItem[]
}

export type EvidenceItem = {
  packet_number?: number
  timestamp?: string
  source?: string
  destination?: string
  protocol?: string
  note?: string
}

export type AnalyzeResponse = {
  file_name: string
  packet_count: number
  analyzed_at?: string
  report?: { html?: string; json?: Record<string, unknown> }
  capture?: {
    first_timestamp?: string
    last_timestamp?: string
    packet_sizes?: { min: number; max: number; mean: number }
    endpoints?: { source: string; destination: string; packets: number }[]
    protocols?: Record<string, number>
  }
  ike?: {
    version?: Param
    exchange_types?: Record<string, number>
    encrypted_ike_packets?: number
    messages?: {
      packet_number?: number
      ike_version?: number
      exchange?: string
      encrypted_payload?: boolean
      timestamp?: string
      source?: string
      destination?: string
    }[]
  }
  evidence?: {
    ikev1?: EvidenceItem[]
    ikev2?: EvidenceItem[]
  }
  evidence_index?: EvidenceItem[]
  ipsec?: {
    ike_udp_500?: number
    natt_udp_4500?: number
    esp_packets?: number
    ah_packets?: number
    natt_present?: boolean
    note?: string
  }
  security_parameters?: Record<string, Param>
  findings?: Finding[]
  threat_matrix?: { severity: string; findings: { id: string; title: string }[] }[]
  risk?: {
    score: number
    level: string
    equation?: string
    formula?: string
    contributors?: {
      finding_id: string
      title: string
      points: number
      evidence_packets?: number[]
    }[]
  }
  security_summary?: {
    security_status?: string
    why?: string
    most_important_action?: string
  }
  recommendations_prioritized?: {
    immediate?: { finding_id: string; recommendation: string; severity: string }[]
    recommended?: { finding_id: string; recommendation: string; severity: string }[]
    informational?: { finding_id: string; recommendation: string; severity: string }[]
  }
  limitations?: string[]
  traffic_analysis?: {
    features?: {
      packet_count?: number
      avg_packet_size?: number
      min_packet_size?: number
      max_packet_size?: number
      packet_size_std?: number
      avg_interarrival_time?: number | null
      packets_per_second?: number | null
      bytes_per_second?: number | null
      traffic_frequency_hz?: number | null
      burst_count?: number
      duration_seconds?: number
      protocol_distribution?: Record<string, number>
      direction_statistics?: {
        packets_a_to_b?: number
        packets_b_to_a?: number
        note?: string
      }
      windows?: { index: number; packets: number; bytes: number }[]
      decrypts_payload?: boolean
    }
    prediction?: string | null
    confidence?: number | null
    model_available?: boolean
    message?: string
    explains?: string
  }
  summary?: Record<string, number>
}

export function paramText(p?: Param): string {
  if (!p) return 'Not detected from available capture'
  if (p.status === 'detected' && (p.value !== null && p.value !== undefined && p.value !== '')) {
    const extra = p.name ? ` (${p.name})` : p.unit ? ` ${p.unit}` : ''
    return `${p.value}${extra}`
  }
  return p.detail || 'Not detected from available capture'
}

export function displayLevel(level?: string): string {
  const l = (level || '').toLowerCase()
  if (l === 'moderate') return 'MEDIUM'
  if (l === 'low') return 'LOW'
  if (l === 'high') return 'HIGH'
  if (l === 'critical') return 'CRITICAL'
  return (level || 'UNKNOWN').toUpperCase()
}

export type ParamBadge = { label: string; tone: 'ok' | 'critical' | 'unknown' }

export function paramBadge(kind: 'encryption' | 'integrity' | 'dh', p?: Param): ParamBadge {
  if (!p || p.status !== 'detected' || p.value === null || p.value === undefined || p.value === '') {
    return { label: 'Not detected', tone: 'unknown' }
  }
  const raw = `${p.value} ${p.name || ''}`.toUpperCase()
  if (kind === 'encryption') {
    if (raw.includes('DES')) return { label: 'Critical Risk', tone: 'critical' }
    return { label: 'Secure', tone: 'ok' }
  }
  if (kind === 'integrity') {
    if (raw.includes('MD5') || raw.includes('SHA1') || raw === 'SHA' || raw.includes('HMAC-SHA1')) {
      return { label: 'Critical Risk', tone: 'critical' }
    }
    return { label: 'Secure', tone: 'ok' }
  }
  if (/\b(1|2|5)\b/.test(String(p.value)) && (p.name || '').toLowerCase().includes('weak')) {
    return { label: 'Critical Risk', tone: 'critical' }
  }
  if (p.name?.toLowerCase().includes('weak')) return { label: 'Critical Risk', tone: 'critical' }
  return { label: 'Secure', tone: 'ok' }
}
