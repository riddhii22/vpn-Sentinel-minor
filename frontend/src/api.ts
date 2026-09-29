import type { AnalyzeResponse } from './types'

const ANALYZE_URL = '/api/analyze'

export async function analyzePcap(file: File, timeoutMs = 60000): Promise<AnalyzeResponse> {
  const body = new FormData()
  body.append('file', file, file.name)
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  let res: Response
  try {
    res = await fetch(ANALYZE_URL, { method: 'POST', body, signal: ctrl.signal })
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      throw new Error('Analysis timed out. Check that the API is running.')
    }
    throw new Error('Cannot reach the analysis API. Start the FastAPI backend on port 48291.')
  } finally {
    clearTimeout(timer)
  }

  let payload: unknown = null
  try {
    payload = await res.json()
  } catch {
    payload = null
  }

  if (!res.ok) {
    const detail =
      payload && typeof payload === 'object' && 'detail' in payload
        ? String((payload as { detail: unknown }).detail)
        : `Request failed (${res.status})`
    throw new Error(detail)
  }
  return payload as AnalyzeResponse
}
