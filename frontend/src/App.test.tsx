import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

describe('VPN Sentinel UI', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('loads the product title and upload action', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'VPN Sentinel' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Analyze VPN' })).toBeDisabled()
    expect(screen.getByText(/Upload a packet capture/i)).toBeInTheDocument()
  })

  it('renders backend risk and findings, not hardcoded scores', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          file_name: 'lab.pcap',
          packet_count: 9,
          ike: {
            version: { status: 'detected', value: 'IKEv1' },
            messages: [{
              packet_number: 1,
              exchange: 'Identity Protection (Main Mode)',
              timestamp: '1.001',
              source: 'a',
              destination: 'b',
            }],
          },
          evidence: { ikev1: [{ packet_number: 1, timestamp: '1', source: 'a', destination: 'b', protocol: 'ISAKMP' }] },
          summary: { esp_packets: 2, ah_packets: 0, udp_500_packets: 3, udp_4500_packets: 0 },
          security_parameters: {
            encryption: { status: 'detected', value: 'AES-CBC-256' },
            integrity: { status: 'detected', value: 'SHA2-256' },
            dh_group: { status: 'detected', value: 20, name: 'ecp384' },
            pfs: { status: 'not_detected', detail: 'Not detected from available capture' },
          },
          findings: [
            {
              id: 'IKE-001',
              rule_id: 'IKE-001',
              title: 'IKEv1 Detected',
              severity: 'critical',
              detected_value: 'IKEv1',
              explanation: 'Version major=1',
              recommendation: 'Migrate to IKEv2.',
              evidence: [{ packet_number: 1, source: 'a', destination: 'b', protocol: 'ISAKMP' }],
            },
          ],
          risk: { score: 30, level: 'moderate', equation: 'min(100, 30) = 30' },
          report: { html: '<html><body>VPN Sentinel 30</body></html>', json: { score: 30 } },
          security_summary: { why: 'IKEv1 present', most_important_action: 'Migrate to IKEv2.' },
          recommendations_prioritized: {
            immediate: [{ finding_id: 'IKE-001', severity: 'critical', recommendation: 'Migrate to IKEv2.' }],
          },
          limitations: ['No ML'],
          traffic_analysis: {
            features: {
              packet_count: 9,
              min_packet_size: 60,
              avg_packet_size: 100,
              max_packet_size: 200,
              packet_size_std: 1,
              avg_interarrival_time: 0.1,
              packets_per_second: 10,
              burst_count: 0,
              duration_seconds: 0.8,
            },
            prediction: null,
            confidence: null,
            model_available: false,
            message: 'AI prediction unavailable — insufficient validated training data.',
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    render(<App />)
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'lab.pcap', { type: 'application/octet-stream' })
    await user.upload(input, file)
    await user.click(screen.getByRole('button', { name: 'Analyze VPN' }))

    expect(await screen.findByText('30/100', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
    expect(screen.getByText('Packets Analyzed')).toBeInTheDocument()
    expect(screen.getByText('Security Score')).toBeInTheDocument()
    expect(screen.getByText('Vulnerabilities Found')).toBeInTheDocument()
    expect(screen.getByText('Handshake Protocol')).toBeInTheDocument()
    expect(screen.getByText('Identity Protection (Main Mode)')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'AI Analysis & Recommendations' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'System Parser Stream' })).toBeInTheDocument()
    expect(screen.getAllByText('Secure').length).toBeGreaterThan(0)
    expect(screen.getByText('IKEv1 Detected')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Download HTML report' })).toBeEnabled()
    expect(screen.getByText('critical', { selector: 'small' })).toBeInTheDocument()
    expect(screen.getByText(/Baseline ML prediction unavailable for this capture/i)).toBeInTheDocument()
    expect(screen.getAllByText('Not detected from available capture').length).toBeGreaterThan(0)
    expect(globalThis.fetch).toHaveBeenCalled()
    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(url).toBe('/api/analyze')
    expect(opts.method).toBe('POST')
  })

  it('shows API error detail', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ detail: 'The capture is empty.' }), { status: 400 }),
    )
    render(<App />)
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    await user.upload(input, new File([new Uint8Array([1, 2, 3])], 'x.pcap'))
    await user.click(screen.getByRole('button', { name: 'Analyze VPN' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The capture is empty.')
    expect(screen.queryByText('30/100')).not.toBeInTheDocument()
  })

  it('fills the handshake table from Demo: IKEv2.pcap', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/samples/IKEv2.pcap')) {
        return new Response(new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1]), { status: 200 })
      }
      return new Response(
        JSON.stringify({
          file_name: 'IKEv2.pcap',
          packet_count: 197,
          ike: {
            version: { status: 'detected', value: 'IKEv2' },
            messages: [
              {
                packet_number: 4,
                timestamp: '12.40',
                source: '10.0.0.1',
                destination: '10.0.0.2',
                exchange: 'IKE_SA_INIT',
              },
            ],
          },
          security_parameters: {
            encryption: { status: 'detected', value: 'AES-GCM-256' },
            integrity: { status: 'detected', value: 'SHA2-256' },
            dh_group: { status: 'detected', value: 14 },
          },
          findings: [],
          risk: { score: 0, level: 'low' },
          security_summary: { why: 'IKEv2 observed', most_important_action: 'Keep current algorithms.' },
          traffic_analysis: {
            model_available: false,
            message: 'AI prediction unavailable — insufficient validated training data.',
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )
    })

    render(<App />)
    await user.click(screen.getByRole('button', { name: 'Demo: IKEv2.pcap' }))
    expect(await screen.findByText('IKE_SA_INIT', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getAllByText('197').length).toBeGreaterThan(0)
    expect(await screen.findByText(/parsed 197 packets/i, {}, { timeout: 4000 })).toBeInTheDocument()
  })
})
