const BASE = ''

async function get(url) {
  const res = await fetch(BASE + url)
  if (!res.ok) throw new Error(`GET ${url} failed: ${res.status}`)
  return res.json()
}

async function post(url, body, headers = {}) {
  const res = await fetch(BASE + url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`POST ${url} failed: ${res.status} ${text}`)
  }
  return res.json()
}

export function connectSSE(url, handlers) {
  const es = new EventSource(BASE + url)
  let manuallyClosed = false

  for (const [event, fn] of Object.entries(handlers)) {
    es.addEventListener(event, (e) => {
      try { fn(JSON.parse(e.data)) } catch { fn(e.data) }
    })
  }
  es.onerror = () => {
    if (!manuallyClosed) {
      handlers.error?.({ message: 'SSE connection lost' })
    }
    es.close()
  }

  const originalClose = es.close.bind(es)
  es.close = () => {
    manuallyClosed = true
    originalClose()
  }

  return es
}

// --- System ---
export const fetchHealth = () => get('/api/system/health')
export const fetchVulnCatalog = () => get('/api/vuln-catalog')
export const fetchCodebaseTypes = () => get('/api/codebase-types')

// --- Scan ---
export const startScan = (config) => post('/api/scan/start', config)
export const fetchScanStatus = (taskId) => get(`/api/scan/status/${taskId}`)
export const streamScan = (taskId, handlers) => connectSSE(`/api/scan/stream/${taskId}`, handlers)

// --- Results ---
export const fetchResults = () => get('/api/results')
export const fetchResultDetail = (filename) => get(`/api/results/${filename}`)

// --- Templates ---
export const fetchTemplates = () => get('/api/templates')
export const fetchTemplateStats = () => get('/api/templates/stats')
export const testTemplateMatch = (language, keyword) => post('/api/templates/test', { language, keyword })

// --- Memory ---
export const fetchMemory = () => get('/api/memory')
export const searchMemory = (query, language, topK = 5) => post('/api/memory/search', { query, language, top_k: topK })
export const fetchMemoryCode = (ruleId) => get(`/api/memory/${ruleId}/code`)
export const exportMemory = () => `${BASE}/api/memory/export`
export const importMemory = async (file, merge = true, apiKey = '') => {
  const form = new FormData()
  form.append('file', file)
  form.append('merge', String(merge))
  const res = await fetch(BASE + '/api/memory/import', {
    method: 'POST',
    headers: apiKey ? { 'X-API-Key': apiKey } : {},
    body: form,
  })
  if (!res.ok) throw new Error('Import failed')
  return res.json()
}
export const clearMemory = (apiKey = '') => post('/api/memory/clear', {}, apiKey ? { 'X-API-Key': apiKey } : {})
export const verifyMemory = (ruleId, apiKey = '') => post(`/api/memory/${ruleId}/verify`, { verified_by: 'web_ui', promote_to: 'verified' }, apiKey ? { 'X-API-Key': apiKey } : {})
export const quarantineMemory = (ruleId, reason = 'web_ui', apiKey = '') => post(`/api/memory/${ruleId}/quarantine`, { reason }, apiKey ? { 'X-API-Key': apiKey } : {})
export const checkMemoryIntegrity = () => get('/api/memory/integrity')
export const fetchTrustStats = () => get('/api/memory/trust-stats')

// --- Benchmark ---
export const fetchBenchmarkPresets = () => get('/api/benchmark/presets')
export const scoreBenchmark = (sarifPath, benchmarkType = 'owasp', expectedCsv = '') => post('/api/benchmark/score', { sarif_path: sarifPath, benchmark_type: benchmarkType, expected_csv: expectedCsv })
export const fetchBenchmarkScores = () => get('/api/benchmark/scores')

// --- Ablation ---
export const startAblation = (config, apiKey = '') => post('/api/ablation/start', config, apiKey ? { 'X-API-Key': apiKey } : {})
export const fetchAblationStatus = (suiteId) => get(`/api/ablation/status/${suiteId}`)
export const streamAblation = (suiteId, handlers) => connectSSE(`/api/ablation/stream/${suiteId}`, handlers)
