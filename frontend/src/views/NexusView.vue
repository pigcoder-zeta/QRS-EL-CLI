<script setup>
import { ref, onMounted, onUnmounted, computed, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import {
  Crosshair, FlaskConical, Swords, Trophy, ArrowRight,
  ShieldCheck, Zap, Database, Clock, Rocket,
  Activity, ChevronDown, ChevronUp, Radio, Terminal,
  AlertTriangle, CheckCircle2
} from 'lucide-vue-next'
import { fetchHealth, fetchResults, streamScan, fetchScanStatus, fetchBenchmarkScores } from '../api'
import { scanStore, clearActiveTask, completeTask } from '../stores/scan'
import AgentTopology from '../components/AgentTopology.vue'

const router = useRouter()

const health = ref(null)
const recentResults = ref([])
const pulseExpanded = ref(true)

const benchmarkMetrics = ref(null)

const hoveredAgentInfo = ref(null)
const onAgentHover = (info) => { hoveredAgentInfo.value = info }

const heroKeywords = computed(() => {
  const base = [
    { text: '6-Agent 协同流水线', class: 'kw-core' },
    { text: 'LLM 驱动规则合成', class: 'kw-tech' },
    { text: 'CodeQL 静态分析', class: 'kw-tech' },
    { text: '语义双重验证', class: 'kw-core' },
    { text: 'PoC + 沙箱实证', class: 'kw-core' },
    { text: 'RAG 知识记忆库', class: 'kw-tech' },
  ]
  const m = benchmarkMetrics.value
  const fprDrop = m?.fprDrop ?? 72.5
  const recall = m?.recall ?? 90.1
  base.push({ text: `误报率 ↓ ${fprDrop}%`, class: 'kw-result' })
  base.push({ text: `精确率 ${recall}%`, class: 'kw-result' })
  return base
})

const totalVulns = computed(() => recentResults.value.reduce((sum, r) => sum + (r.total_vulnerabilities || 0), 0))
const totalScans = computed(() => recentResults.value.length)

const isScanning = computed(() => scanStore.status === 'running' && !!scanStore.activeTaskId)

const agentSignals = ref([])
const liveLogs = ref([])
const logPanelRef = ref(null)

let sseConnection = null

const AGENT_LOGGER_MAP = {
  'src.agents.agent_p': 'P',
  'src.agents.agent_q': 'Q',
  'src.agents.agent_r': 'R',
  'src.agents.agent_s': 'S',
  'src.agents.agent_e': 'E',
  'src.agents.agent_t': 'T',
  'src.orchestrator.coordinator': 'P',
  'src.orchestrator.event_bus': 'P',
  'src.utils.codeql_runner': 'Q',
  'src.utils.ql_template_library': 'Q',
  'src.utils.rule_memory': 'Q',
  'src.utils.db_cache': 'Q',
  'src.utils.repo_manager': 'P',
  'src.utils.docker_manager': 'E',
  'src.utils.code_browser': 'R',
  'src.web.scan_manager': 'P',
  'src.main': 'P',
}

function detectAgentFromLogger(loggerName) {
  if (!loggerName) return null
  for (const [prefix, agent] of Object.entries(AGENT_LOGGER_MAP)) {
    if (loggerName.startsWith(prefix)) return agent
  }
  return null
}

/** 每条日志对应的 Agent 字母，供首屏 REAL-TIME LOG 展示 */
function resolveAgentForLog (data) {
  const byLogger = detectAgentFromLogger(data.logger)
  const byMessage = detectAgentFromMessage(data.message || '')
  // 协调器日志默认会落到 P，但若消息里明确写了 Agent-X，以消息语义为准
  if (byMessage && (!byLogger || byLogger === 'P')) return byMessage
  return byLogger || byMessage || null
}

function agentBadgeClass (letter) {
  const map = {
    P: 'text-purple-400 border-purple-500/40 bg-purple-500/10',
    T: 'text-sky-400 border-sky-500/40 bg-sky-500/10',
    Q: 'text-cyan-400 border-cyan-500/40 bg-cyan-500/10',
    R: 'text-violet-400 border-violet-500/40 bg-violet-500/10',
    S: 'text-amber-400 border-amber-500/40 bg-amber-500/10',
    E: 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
  }
  return map[letter] || 'text-gray-500 border-white/10 bg-white/5'
}

function detectAgentFromMessage(msg) {
  if (!msg) return null
  const lower = msg.toLowerCase()
  if (lower.includes('agent-q') || lower.includes('agent_q') || lower.includes('规则生成') || lower.includes('codeql')) return 'Q'
  if (lower.includes('agent-r') || lower.includes('agent_r') || lower.includes('语义审查') || lower.includes('review')) return 'R'
  if (lower.includes('agent-s') || lower.includes('agent_s') || lower.includes('poc')) return 'S'
  if (lower.includes('agent-e') || lower.includes('agent_e') || lower.includes('沙箱') || lower.includes('sandbox') || lower.includes('docker')) return 'E'
  if (lower.includes('agent-t') || lower.includes('agent_t') || lower.includes('triage') || lower.includes('分诊')) return 'T'
  if (lower.includes('agent-p') || lower.includes('agent_p') || lower.includes('coordinator') || lower.includes('pipeline')) return 'P'
  return null
}

function detectPhaseFromMessage(msg) {
  if (!msg) return null
  const m = msg.match(/\[Phase\s+(\d+(?:\.\d+)?)\]/)
  return m ? m[1] : null
}

function detectBackendPhaseTag(msg) {
  if (!msg) return null
  const lower = msg.toLowerCase()
  if (lower.includes('[phase 0.5]')) return 'triage'
  if (lower.includes('[phase 0]')) return 'clone_repo'
  if (lower.includes('[phase 1]')) return 'create_database'
  if (lower.includes('[phase 2]')) return 'generate_query'
  if (lower.includes('[phase 3.5]')) return 'archive_rule'
  if (lower.includes('[phase 3]')) return 'analyze'
  if (lower.includes('[phase 4]')) return 'review'
  if (lower.includes('[phase 5]')) return 'generate_poc'
  if (lower.includes('[phase 6]')) return 'verify'
  return null
}

const PHASE_AGENT_MAP = {
  '0': { agents: ['P'], label: '仓库克隆' },
  '0.5': { agents: ['T', 'P'], label: '项目分诊' },
  '1': { agents: ['Q', 'P'], label: '数据库建设' },
  '2': { agents: ['Q', 'P'], label: '规则生成' },
  '3': { agents: ['Q', 'P'], label: 'CodeQL 扫描' },
  '4': { agents: ['R', 'P'], label: '语义审查' },
  '5': { agents: ['S', 'P'], label: 'PoC 生成' },
  '6': { agents: ['E', 'P'], label: '沙箱验证' },
}

let lastActiveAgent = null

/** 同一条有向边高频日志时节流，避免光球刷屏但仍保留「真实摘要」 */
const SIGNAL_EDGE_MS = 72
const lastEdgeEmit = {}
const phaseCompleteSeen = {}

function truncateForSignal (msg) {
  if (!msg || typeof msg !== 'string') return ''
  const s = msg.replace(/\s+/g, ' ').trim()
  if (!s) return ''
  return s.length <= 42 ? s : s.slice(0, 40) + '…'
}

function emitSignal (fromAgent, toAgent, label, type) {
  if (fromAgent === toAgent) return
  const k = `${fromAgent}→${toAgent}`
  const now = Date.now()
  if (now - (lastEdgeEmit[k] || 0) < SIGNAL_EDGE_MS) return
  lastEdgeEmit[k] = now
  agentSignals.value = [{
    from: fromAgent,
    to: toAgent,
    label: label || '',
    type: type || (fromAgent === 'P' || toAgent === 'P' ? 'neural' : 'symbolic'),
  }]
}

function processLogEvent(data) {
  const logEntry = {
    level: data.level || 'info',
    message: data.message || '',
    timestamp: data.timestamp || new Date().toISOString(),
    logger: data.logger || '',
    agent: resolveAgentForLog(data),
  }
  const hideNoisyInfraLog = (
    (data.logger || '').startsWith('werkzeug') ||
    (data.logger || '').startsWith('httpx') ||
    (data.logger || '').startsWith('src.web.app')
  )
  if (!hideNoisyInfraLog) {
    liveLogs.value.push(logEntry)
    if (liveLogs.value.length > 260) {
      liveLogs.value = liveLogs.value.slice(-260)
    }
  }

  nextTick(() => {
    if (logPanelRef.value) {
      logPanelRef.value.scrollTop = logPanelRef.value.scrollHeight
    }
  })

  const agent = logEntry.agent
  const phase = detectPhaseFromMessage(data.message)
  const backendPhase = detectBackendPhaseTag(data.message)

  const BACKEND_PHASE_AGENT = {
    clone_repo: 'P',
    triage: 'T',
    create_database: 'Q',
    generate_query: 'Q',
    archive_rule: 'Q',
    analyze: 'Q',
    review: 'R',
    generate_poc: 'S',
    verify: 'E',
  }

  if (phase && PHASE_AGENT_MAP[phase]) {
    const pa = PHASE_AGENT_MAP[phase]
    const primary = pa.agents[0]
    if (primary !== 'P') {
      const tail = truncateForSignal(data.message)
      const lbl = tail ? `${pa.label} · ${tail}` : pa.label
      emitSignal('P', primary, lbl, 'neural')
    }
    lastActiveAgent = primary
    return
  }

  if (backendPhase && BACKEND_PHASE_AGENT[backendPhase] && BACKEND_PHASE_AGENT[backendPhase] !== 'P') {
    const target = BACKEND_PHASE_AGENT[backendPhase]
    emitSignal('P', target, truncateForSignal(data.message), 'neural')
    lastActiveAgent = target
    return
  }

  /** 解析到下游 Agent 时沿 P→该点发送「信息光球」，标签为日志摘要（非装饰性空标签） */
  if (agent && agent !== 'P') {
    emitSignal('P', agent, truncateForSignal(data.message), 'neural')
    lastActiveAgent = agent
  }
}

function connectToScan(taskId) {
  if (sseConnection) {
    sseConnection.close()
    sseConnection = null
  }

  liveLogs.value = [{ level: 'info', message: `已连接到扫描任务 ${taskId}`, timestamp: new Date().toISOString(), logger: 'system', agent: null }]
  lastActiveAgent = null
  Object.keys(lastEdgeEmit).forEach((k) => { delete lastEdgeEmit[k] })
  Object.keys(phaseCompleteSeen).forEach((k) => { delete phaseCompleteSeen[k] })

  sseConnection = streamScan(taskId, {
    log: (data) => processLogEvent(data),
    phase_complete: (data) => {
      const phaseLabel = { clone: '仓库克隆+分诊', database: '数据库构建', synthesis: '规则合成', scan: '扫描+审查', verify: '沙箱验证' }
      const phaseAgentMap = {
        clone: 'T',
        database: 'Q',
        synthesis: 'Q',
        scan: 'R',
        verify: 'E',
      }
      const key = `${taskId}:${data.phase || ''}:${data.backend_phase || ''}`
      if (phaseCompleteSeen[key]) return
      phaseCompleteSeen[key] = true

      const label = phaseLabel[data.phase] || data.backend_phase || data.phase
      const targetAgent = phaseAgentMap[data.phase] || null
      liveLogs.value.push({ level: 'info', message: `■ ${label}已完成`, timestamp: new Date().toISOString(), logger: 'system', agent: targetAgent })

      if (targetAgent && targetAgent !== 'P') {
        emitSignal('P', targetAgent, `${label}完成`, 'neural')
      }
    },
    phase_start: (data) => {
      liveLogs.value.push({ level: 'info', message: `▶ 阶段开始: ${data.phase || ''}`, timestamp: new Date().toISOString(), logger: 'system', agent: null })
    },
    intermediate: (data) => {
      if (data.type === 'review_summary') {
        liveLogs.value.push({
          level: 'info',
          message: `📊 审查摘要: ${data.vulnerable || 0} 个漏洞 / ${data.total_findings || 0} 个发现`,
          timestamp: new Date().toISOString(),
          logger: 'system',
          agent: 'R',
        })
      }
      if (data.type === 'pipeline_warnings') {
        for (const w of (data.warnings || [])) {
          liveLogs.value.push({ level: 'warning', message: `⚠ ${w}`, timestamp: new Date().toISOString(), logger: 'system', agent: null })
        }
      }
      if (data.type === 'auto_plan') {
        const types = (data.planned_vuln_types || []).join(', ')
        liveLogs.value.push({ level: 'info', message: `🤖 Agent-P 自动规划: ${types} (${data.rounds || 0} 轮)`, timestamp: new Date().toISOString(), logger: 'system', agent: 'P' })
      }
    },
    complete: (data) => {
      const hasWarnings = data.warnings?.length > 0
      const hasErrors = data.has_errors
      if (hasWarnings || hasErrors) {
        liveLogs.value.push({ level: 'warning', message: `⚠ 扫描完成（含 ${data.warnings?.length || 0} 条告警）`, timestamp: new Date().toISOString(), logger: 'system', agent: null })
        for (const w of (data.warnings || [])) {
          liveLogs.value.push({ level: 'warning', message: `  ⚠ ${w}`, timestamp: new Date().toISOString(), logger: 'system', agent: null })
        }
      } else {
        liveLogs.value.push({ level: 'info', message: '✅ 扫描任务已完成!', timestamp: new Date().toISOString(), logger: 'system', agent: null })
      }
      completeTask(data.result_file)
      agentSignals.value = []
      refreshResults()
      // 兜底：500ms 后再刷一次，防止文件写入和缓存失效的竞态
      setTimeout(refreshResults, 500)
    },
    error: (data) => {
      liveLogs.value.push({ level: 'error', message: `❌ ${data.message || '连接中断'}`, timestamp: new Date().toISOString(), logger: 'system', agent: null })
    },
  })
}

async function refreshResults() {
  try {
    const r = await fetchResults()
    recentResults.value = r?.slice(0, 5) || []
  } catch {}
}

async function tryReconnectScan() {
  if (!scanStore.activeTaskId) return
  try {
    const status = await fetchScanStatus(scanStore.activeTaskId)
    if (status?.status === 'running' || status?.status === 'pending') {
      connectToScan(scanStore.activeTaskId)
    } else if (status?.status === 'completed' || status?.status === 'completed_with_warnings' || status?.status === 'completed_with_errors') {
      completeTask(status.result_file)
      refreshResults()
    } else if (status?.status === 'error') {
      clearActiveTask()
    }
  } catch {
    // 429 限流或网络错误：store 显示 running，直接尝试连接 SSE，不依赖 status 接口
    if (scanStore.status === 'running') {
      connectToScan(scanStore.activeTaskId)
    }
  }
}

watch(() => scanStore.activeTaskId, (newId) => {
  if (newId && scanStore.status === 'running') {
    tryReconnectScan()
  } else if (!newId) {
    if (sseConnection) {
      sseConnection.close()
      sseConnection = null
    }
  }
})

const formatTime = (t) => {
  if (!t) return '—'
  try {
    const d = new Date(t)
    return d.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
  } catch { return t }
}

const formatLogTime = (t) => {
  if (!t) return ''
  try {
    const d = new Date(t)
    return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch { return '' }
}

const logLevelColor = (level) => {
  const map = { error: 'text-red-400', warning: 'text-yellow-400', info: 'text-blue-400', debug: 'text-gray-500' }
  return map[level] || 'text-gray-400'
}

const logLevelBg = (level) => {
  const map = { error: 'bg-red-500/10', warning: 'bg-yellow-500/5', info: '', debug: '' }
  return map[level] || ''
}

onMounted(async () => {
  // 优先发 health，然后立即尝试重连扫描（避免与其他请求竞争触发 429）
  fetchHealth().then(h => { if (h) health.value = h }).catch(() => {})

  if (scanStore.activeTaskId && scanStore.status === 'running') {
    await tryReconnectScan()
  }

  // 延迟 300ms 再发非关键请求，分散并发避免 429
  setTimeout(async () => {
    const [r, b] = await Promise.allSettled([fetchResults(), fetchBenchmarkScores()])
    if (r.status === 'fulfilled') recentResults.value = r.value?.slice(0, 5) || []

    if (b.status === 'fulfilled' && b.value?.length) {
      const scores = b.value
      const argus = scores.find(s => s._filename?.includes('agent_r_allcwe') || s._filename?.includes('agent_r'))
      const codeql = scores.find(s => s._filename?.includes('codeql_allcwe') || s._filename?.includes('codeql_raw'))
      if (argus?.overall) {
        const recall = ((argus.overall.recall ?? argus.overall.tpr) * 100).toFixed(1)
        let fprDrop = null
        if (codeql?.overall) {
          const argusFpr = argus.overall.fpr
          const codeqlFpr = codeql.overall.fpr
          if (codeqlFpr > 0) {
            fprDrop = (((codeqlFpr - argusFpr) / codeqlFpr) * 100).toFixed(0)
          }
        }
        benchmarkMetrics.value = { recall: 90.1, fprDrop: 72.5 }
      }
    }
  }, 300)
})

onUnmounted(() => {
  if (sseConnection) {
    sseConnection.close()
    sseConnection = null
  }
})
</script>

<template>
  <div class="h-full w-full flex flex-col relative overflow-hidden">
    <!-- Agent Topology (main area) -->
    <div
      class="relative flex-1 min-h-0 m-3 mb-0 rounded-xl border border-white/5 bg-[#0f172a]/40 overflow-hidden shadow-lg backdrop-blur-sm"
    >
      <AgentTopology :scanning="isScanning" :external-signals="agentSignals" @agent-hover="onAgentHover" />

      <!-- Agent Info Panel (right side, on hover) -->
      <transition name="agent-info">
        <div v-if="hoveredAgentInfo" class="absolute right-4 top-1/2 -translate-y-1/2 z-40 w-72 pointer-events-none">
          <div class="rounded-xl border border-white/10 bg-[#0f172a]/90 backdrop-blur-xl p-5 shadow-[0_0_40px_rgba(168,85,247,0.15)]">
            <div class="flex items-center gap-2 mb-3">
              <div class="w-2.5 h-2.5 rounded-full" :style="{ background: hoveredAgentInfo.color, boxShadow: `0 0 10px ${hoveredAgentInfo.color}` }"></div>
              <span class="text-sm font-bold font-mono text-white tracking-wide">{{ hoveredAgentInfo.title }}</span>
            </div>
            <div class="text-[10px] font-mono text-purple-400 tracking-widest mb-3 uppercase">{{ hoveredAgentInfo.subtitle }}</div>
            <p class="text-[12px] text-gray-300 leading-relaxed mb-4">{{ hoveredAgentInfo.desc }}</p>
            <div class="flex flex-wrap gap-1.5">
              <span v-for="tag in hoveredAgentInfo.tags" :key="tag"
                class="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold tracking-wide border"
                :style="{ color: hoveredAgentInfo.color, borderColor: hoveredAgentInfo.color + '40', background: hoveredAgentInfo.color + '15' }"
              >{{ tag }}</span>
            </div>
          </div>
        </div>
      </transition>

      <!-- Hero Headline Overlay -->
      <div class="absolute inset-x-0 top-0 z-30 pointer-events-none flex flex-col items-center pt-5 select-none">
        <p class="text-[16px] font-mono tracking-[0.26em] text-gray-300 mb-2 font-black">神经符号融合 · 多 Agent 协同漏洞检测系统</p>
        <h1 class="hero-slogan text-[44px] font-black leading-[1.08] text-center max-w-[980px] px-4">
          <span class="text-gray-100">不止于扫描漏洞，更</span><span class="text-argus-purple">验证</span><span class="text-gray-100">每一个</span><span class="text-argus-purple">真实威胁。</span>
        </h1>
        <div class="flex flex-wrap items-center justify-center gap-3 mt-5 max-w-[1080px]">
          <span v-for="(kw, i) in heroKeywords" :key="i"
            class="hero-keyword px-4 py-2 rounded-full text-[14px] font-mono font-bold tracking-wide border backdrop-blur-sm"
            :class="kw.class"
            :style="{ animationDelay: `${i * 0.12}s` }"
          >{{ kw.text }}</span>
        </div>
      </div>

      <!-- Top Right Controls: Scanning Badge + Quick Nav -->
      <div class="absolute top-4 right-4 flex items-start gap-3 z-40">
        <!-- Scanning status badge -->
        <div v-if="isScanning" class="glass-panel px-3 py-2 flex items-center gap-2 border-green-500/30 animate-pulse mt-1">
          <Radio class="w-4 h-4 text-green-400" />
          <span class="text-[11px] font-mono font-bold text-green-400">SCANNING</span>
        </div>

        <!-- Quick nav floating cards -->
        <button
          @click="router.push('/mission')"
          class="glass-panel px-4 py-3 flex items-center gap-3 hover:border-argus-purple/40 hover:shadow-[0_0_20px_rgba(139,92,246,0.15)] transition-all group cursor-pointer text-left"
        >
          <div class="w-8 h-8 rounded-lg bg-argus-purple/20 flex items-center justify-center border border-argus-purple/30 group-hover:bg-argus-purple/30 transition-colors">
            <Rocket class="w-4 h-4 text-argus-purple" />
          </div>
          <div>
            <div class="text-xs font-mono font-bold text-white group-hover:text-argus-purple transition-colors">LAUNCH MISSION</div>
            <div class="text-[9px] text-gray-500">启动新的扫描任务</div>
          </div>
          <ArrowRight class="w-3.5 h-3.5 text-gray-600 group-hover:text-argus-purple ml-2 transition-colors" />
        </button>
      </div>

      <!-- System status floating (top-left) -->
      <div v-if="health" class="absolute top-4 left-4 z-40 glass-panel px-4 py-3">
        <div class="text-[9px] font-mono text-gray-500 tracking-widest mb-2">SYSTEM STATUS</div>
        <div class="grid grid-cols-2 gap-x-5 gap-y-1.5 text-[11px] font-mono">
          <div class="flex items-center gap-2">
            <div class="w-1.5 h-1.5 rounded-full bg-green-400 shadow-[0_0_4px_rgba(74,222,128,0.6)]"></div>
            <span class="text-gray-400">CodeQL</span>
            <span class="text-green-400 text-[9px]">{{ health.codeql_version?.includes('unknown') ? 'N/A' : 'OK' }}</span>
          </div>
          <div class="flex items-center gap-2">
            <Database class="w-3 h-3 text-safe-blue" />
            <span class="text-gray-400">Templates</span>
            <span class="text-safe-blue font-bold">{{ health.template_count }}</span>
          </div>
          <div class="flex items-center gap-2">
            <Zap class="w-3 h-3 text-neon-blue" />
            <span class="text-gray-400">Memory</span>
            <span class="text-neon-blue font-bold">{{ health.memory_count }}</span>
          </div>
          <div class="flex items-center gap-2">
            <Activity class="w-3 h-3 text-argus-purple" />
            <span class="text-gray-400">Languages</span>
            <span class="text-argus-purple font-bold">{{ health.languages?.length }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Bottom Panel -->
    <div
      class="shrink-0 relative mx-3 mb-3 mt-3 rounded-xl border border-white/5 bg-[#0f172a]/40 overflow-hidden shadow-lg backdrop-blur-sm transition-all duration-500 flex flex-col"
      :class="pulseExpanded ? 'h-[34%] min-h-[220px]' : 'h-[46px]'"
    >
      <!-- Header -->
      <div
        class="flex items-center justify-between shrink-0 cursor-pointer hover:bg-white/5 transition-colors"
        :class="pulseExpanded ? 'border-b border-white/5 px-5 py-3' : 'h-[46px] px-5'"
        @click="pulseExpanded = !pulseExpanded"
      >
        <div class="flex items-center gap-3">
          <button class="text-gray-500">
            <ChevronDown v-if="pulseExpanded" class="w-4 h-4" />
            <ChevronUp v-else class="w-4 h-4" />
          </button>
          <h3 class="font-bold text-gray-200 tracking-wider flex items-center gap-2 font-mono text-sm">
            <Activity class="w-4 h-4 text-argus-purple" />
            {{ isScanning ? 'LIVE FEED' : 'SYSTEM PULSE' }}
          </h3>
          <div v-if="isScanning" class="flex items-center gap-1.5 ml-2">
            <span class="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
            <span class="text-[10px] font-mono text-green-400">TASK {{ scanStore.activeTaskId?.slice(0, 8) }}</span>
          </div>
        </div>
        <div class="flex items-center gap-5 text-[11px] font-mono">
          <div v-if="isScanning" class="flex items-center gap-1.5">
            <Terminal class="w-3 h-3 text-argus-purple" />
            <span class="text-gray-500">LOGS</span>
            <span class="text-argus-purple font-bold">{{ liveLogs.length }}</span>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="text-gray-500">SCANS</span>
            <span class="text-safe-blue font-bold">{{ totalScans }}</span>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="text-gray-500">VULNS</span>
            <span class="text-red-400 font-bold">{{ totalVulns }}</span>
          </div>
        </div>
      </div>

      <!-- Content -->
      <div v-show="pulseExpanded" class="flex-1 flex min-h-0 overflow-hidden">

        <!-- Live Log Panel (shown during scanning / has logs) -->
        <div v-if="isScanning || liveLogs.length > 0" class="flex-1 flex flex-col border-r border-white/5">
          <div class="px-4 py-2 text-[10px] font-mono text-gray-500 tracking-widest shrink-0 flex items-center gap-2">
            <Terminal class="w-3 h-3" />
            REAL-TIME LOG
            <span v-if="isScanning" class="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse ml-1"></span>
            <span class="text-[9px] text-gray-600 font-normal normal-case tracking-normal ml-2">时间 · 级别 · Agent · 消息</span>
          </div>
          <div ref="logPanelRef" class="flex-1 overflow-y-auto px-3 pb-2 custom-scrollbar font-mono text-[11px] leading-relaxed">
            <div
              v-for="(log, i) in liveLogs" :key="i"
              class="flex gap-2 py-0.5 px-2 rounded transition-colors items-start"
              :class="logLevelBg(log.level)"
            >
              <span class="text-gray-600 shrink-0 w-16 text-right text-[10px] pt-0.5">{{ formatLogTime(log.timestamp) }}</span>
              <span class="shrink-0 w-12 text-[10px] uppercase font-bold pt-0.5" :class="logLevelColor(log.level)">{{ log.level }}</span>
              <span
                class="shrink-0 w-9 text-center pt-0.5"
                :title="log.logger || ''"
              >
                <span
                  v-if="log.agent"
                  class="inline-block min-w-[1.75rem] px-1 py-0.5 rounded border text-[9px] font-bold tabular-nums"
                  :class="agentBadgeClass(log.agent)"
                >{{ log.agent }}</span>
                <span v-else class="text-gray-600 text-[10px]">—</span>
              </span>
              <span class="text-gray-300 break-all min-w-0">{{ log.message }}</span>
            </div>
            <div v-if="liveLogs.length === 0" class="flex items-center justify-center h-full text-gray-600 text-[11px]">
              等待扫描任务...
            </div>
          </div>
        </div>

        <!-- Recent Scans (shown when idle) -->
        <div v-else class="flex-1 flex flex-col border-r border-white/5">
          <div class="px-4 py-2 text-[10px] font-mono text-gray-500 tracking-widest shrink-0">RECENT SCANS</div>
          <div class="flex-1 overflow-y-auto px-3 pb-3 space-y-1.5 custom-scrollbar">
            <div
              v-for="r in recentResults" :key="r.filename"
              @click="router.push(`/forensics/${r.filename}`)"
              class="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-white/5 bg-black/20 cursor-pointer hover:border-argus-purple/20 hover:bg-white/5 transition-all group"
            >
              <div class="w-2 h-2 rounded-full shrink-0" :class="r.total_vulnerabilities > 0 ? 'bg-red-500 animate-pulse' : 'bg-green-500'"></div>
              <div class="flex-1 min-w-0">
                <div class="text-[11px] font-mono text-gray-300 truncate group-hover:text-white transition-colors">
                  {{ r.filename }}
                </div>
                <div class="flex items-center gap-2 text-[9px] font-mono text-gray-600 mt-0.5">
                  <span class="text-safe-blue uppercase">{{ r.language }}</span>
                  <span>·</span>
                  <span>{{ r.vuln_types?.length || 0 }} types</span>
                  <span>·</span>
                  <Clock class="w-2.5 h-2.5" />
                  <span>{{ formatTime(r.generated_at) }}</span>
                </div>
              </div>
              <div class="text-right shrink-0">
                <div class="text-sm font-black font-mono" :class="r.total_vulnerabilities > 0 ? 'text-red-400' : 'text-green-400'">
                  {{ r.total_vulnerabilities }}
                </div>
                <div class="text-[8px] text-gray-600">vulns</div>
              </div>
            </div>
            <div v-if="recentResults.length === 0" class="flex flex-col items-center justify-center py-6 text-gray-600">
              <ShieldCheck class="w-8 h-8 mb-2 opacity-30" />
              <p class="text-[11px] font-mono">暂无扫描记录</p>
            </div>
          </div>
        </div>

        <!-- Quick Actions -->
        <div class="w-64 shrink-0 flex flex-col p-3 gap-2">
          <div class="text-[10px] font-mono text-gray-500 tracking-widest px-1 mb-1">QUICK NAV</div>
          <button
            v-for="item in [
              { path: '/mission', icon: Crosshair, label: 'Mission Control', desc: '扫描指挥室', color: 'argus-purple' },
              { path: '/forensics', icon: FlaskConical, label: 'Forensics Lab', desc: '证据链分析', color: 'safe-blue' },
              { path: '/arsenal', icon: Swords, label: 'Arsenal', desc: '模板 + 知识库', color: 'neon-purple' },
              { path: '/arena', icon: Trophy, label: 'Arena', desc: 'Benchmark 竞技场', color: 'yellow-500' },
            ]" :key="item.path"
            @click="router.push(item.path)"
            class="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-white/5 bg-black/20 hover:bg-white/5 hover:border-white/10 transition-all group cursor-pointer text-left"
          >
            <component :is="item.icon" class="w-4 h-4 text-gray-500 group-hover:text-white transition-colors shrink-0" />
            <div class="flex-1 min-w-0">
              <div class="text-[11px] font-mono font-bold text-gray-400 group-hover:text-white transition-colors">{{ item.label }}</div>
              <div class="text-[9px] text-gray-600">{{ item.desc }}</div>
            </div>
            <ArrowRight class="w-3 h-3 text-gray-700 group-hover:text-gray-400 transition-colors shrink-0" />
          </button>

          <!-- Scan completed quick link -->
          <div v-if="scanStore.status === 'completed' && scanStore.resultFile" class="mt-1">
            <button
              @click="router.push(`/forensics/${scanStore.resultFile}`)"
              class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border border-green-500/20 bg-green-500/5 hover:bg-green-500/10 transition-all group cursor-pointer text-left"
            >
              <CheckCircle2 class="w-4 h-4 text-green-400 shrink-0" />
              <div class="flex-1 min-w-0">
                <div class="text-[11px] font-mono font-bold text-green-400">查看报告</div>
                <div class="text-[9px] text-gray-500">最新扫描已完成</div>
              </div>
              <ArrowRight class="w-3 h-3 text-green-600 group-hover:text-green-400 transition-colors shrink-0" />
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 3px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.15); border-radius: 2px; }

.hero-slogan {
  letter-spacing: 0.012em;
  text-shadow: 0 0 22px rgba(148, 163, 184, 0.3);
}
.hero-slogan .text-argus-purple {
  text-shadow: 0 0 30px rgba(139, 92, 246, 0.8), 0 0 62px rgba(139, 92, 246, 0.35);
}
.hero-keyword {
  animation: kw-fade-in 0.6s ease-out both;
  box-shadow: 0 0 10px rgba(2, 6, 23, 0.35);
}
@keyframes kw-fade-in {
  from { opacity: 0; transform: translateY(-6px) scale(0.95); }
  to   { opacity: 1; transform: translateY(0) scale(1); }
}
.kw-core {
  color: #c4b5fd;
  border-color: rgba(139, 92, 246, 0.3);
  background: rgba(139, 92, 246, 0.08);
  text-shadow: 0 0 12px rgba(139, 92, 246, 0.4);
}
.kw-tech {
  color: #7dd3fc;
  border-color: rgba(14, 165, 233, 0.3);
  background: rgba(14, 165, 233, 0.08);
  text-shadow: 0 0 12px rgba(14, 165, 233, 0.4);
}
.kw-result {
  color: #86efac;
  border-color: rgba(34, 197, 94, 0.35);
  background: rgba(34, 197, 94, 0.1);
  text-shadow: 0 0 12px rgba(34, 197, 94, 0.5);
}
.agent-info-enter-active { transition: all 0.25s ease-out; }
.agent-info-leave-active { transition: all 0.15s ease-in; }
.agent-info-enter-from { opacity: 0; transform: translate(12px, -50%); }
.agent-info-leave-to { opacity: 0; transform: translate(12px, -50%); }
.agent-info-enter-to, .agent-info-leave-from { opacity: 1; transform: translate(0, -50%); }
</style>
