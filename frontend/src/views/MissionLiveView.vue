<script setup>
import { ref, onMounted, onUnmounted, nextTick, computed } from 'vue'
import { useRouter } from 'vue-router'
import {
  Eye, Code, Terminal, Activity, ShieldCheck, BrainCircuit,
  CheckCircle2, Loader2, Circle, AlertTriangle, ArrowRight
} from 'lucide-vue-next'
import { streamScan, fetchScanStatus } from '../api'
import { completeTask, failTask, scanStore } from '../stores/scan'

const props = defineProps({ id: String })
const router = useRouter()

const phases = ref([
  { key: 'clone', label: '仓库克隆 + 分诊', status: 'pending' },
  { key: 'database', label: 'CodeQL 数据库构建', status: 'pending' },
  { key: 'synthesis', label: 'Agent-Q 规则合成', status: 'pending' },
  { key: 'scan', label: 'CodeQL 扫描 + Agent-R 审查', status: 'pending' },
  { key: 'verify', label: 'Agent-S/E 沙箱验证', status: 'pending' },
])

const agentActivity = ref([
  { id: 'P', label: 'Agent-P', icon: BrainCircuit, active: false, status: '' },
  { id: 'T', label: 'Agent-T', icon: Eye, active: false, status: '' },
  { id: 'Q', label: 'Agent-Q', icon: Code, active: false, status: '' },
  { id: 'R', label: 'Agent-R', icon: Activity, active: false, status: '' },
  { id: 'S', label: 'Agent-S', icon: Terminal, active: false, status: '' },
  { id: 'E', label: 'Agent-E', icon: ShieldCheck, active: false, status: '' },
])

const logs = ref([])
const reviewSummary = ref(null)
const pipelineWarnings = ref([])
const taskStatus = ref('running')
const resultFile = ref('')
const missionComplete = ref(false)
let es = null
let logContainer = null

const addLog = (entry) => {
  logs.value.push(entry)
  if (logs.value.length > 500) logs.value.shift()
  nextTick(() => {
    if (logContainer) logContainer.scrollTop = logContainer.scrollHeight
  })
}

const detectAgent = (msg) => {
  const lower = msg.toLowerCase()
  if (lower.includes('agent-p') || lower.includes('agent_p') || lower.includes('planner')) return 'P'
  if (lower.includes('agent-t') || lower.includes('agent_t') || lower.includes('triage')) return 'T'
  if (lower.includes('agent-q') || lower.includes('agent_q') || lower.includes('query') || lower.includes('规则合成')) return 'Q'
  if (lower.includes('agent-r') || lower.includes('agent_r') || lower.includes('review') || lower.includes('审查')) return 'R'
  if (lower.includes('agent-s') || lower.includes('agent_s') || lower.includes('poc') || lower.includes('synthesize')) return 'S'
  if (lower.includes('agent-e') || lower.includes('agent_e') || lower.includes('sandbox') || lower.includes('docker')) return 'E'
  return null
}

const detectPhase = (msg) => {
  const lower = msg.toLowerCase()
  if (lower.includes('clone') || lower.includes('克隆') || lower.includes('triage') || lower.includes('分诊')) return 'clone'
  if (lower.includes('database') || lower.includes('数据库') || lower.includes('building')) return 'database'
  if (lower.includes('synth') || lower.includes('规则') || lower.includes('template') || lower.includes('compil')) return 'synthesis'
  if (lower.includes('scan') || lower.includes('扫描') || lower.includes('review') || lower.includes('审查') || lower.includes('sarif')) return 'scan'
  if (lower.includes('poc') || lower.includes('sandbox') || lower.includes('docker') || lower.includes('verif')) return 'verify'
  return null
}

const getLogClass = (level) => {
  if (level === 'error') return 'text-red-400'
  if (level === 'warning') return 'text-yellow-400'
  return 'text-gray-400'
}

const highlightLog = (msg) => {
  return msg
    .replace(/(error|错误|失败|failed)/gi, '<span class="text-red-400 font-bold">$1</span>')
    .replace(/(warning|警告)/gi, '<span class="text-yellow-400">$1</span>')
    .replace(/(Agent-[PTQRSE])/g, '<span class="text-argus-purple font-bold">$1</span>')
    .replace(/(success|成功|completed|完成)/gi, '<span class="text-green-400">$1</span>')
}

onMounted(async () => {
  try {
    const status = await fetchScanStatus(props.id)
    if (status?.status === 'completed' || status?.status === 'completed_with_warnings' || status?.status === 'completed_with_errors') {
      taskStatus.value = status.status
      resultFile.value = status.result_file || ''
      phases.value.forEach(p => p.status = 'done')
      completeTask(status.result_file)
      addLog({ level: 'info', message: 'Task already completed.', html: '<span class="text-green-400 font-bold">✓ Task already completed</span>' })
      setTimeout(() => { missionComplete.value = true }, 300)
      return
    }
    if (status?.status === 'error') {
      taskStatus.value = 'error'
      failTask()
      addLog({ level: 'error', message: status.error || 'Task failed', html: `<span class="text-red-400 font-bold">ERROR: ${status.error || 'Task failed'}</span>` })
      return
    }
  } catch {}

  es = streamScan(props.id, {
    log: (data) => {
      addLog({ ...data, html: highlightLog(data.message) })
      const agentId = detectAgent(data.message)
      if (agentId) {
        agentActivity.value.forEach(a => a.active = a.id === agentId)
        const agent = agentActivity.value.find(a => a.id === agentId)
        if (agent) agent.status = data.message.slice(0, 60)
      }
    },
    phase_complete: (data) => {
      const key = data.phase
      const idx = phases.value.findIndex(p => p.key === key)
      if (idx < 0) return
      for (let i = 0; i < idx; i++) phases.value[i].status = 'done'
      phases.value[idx].status = 'active'
    },
    phase_start: (data) => {
      addLog({ level: 'info', message: `Pipeline started: ${data.total} vuln types`, html: `<span class="text-safe-blue font-bold">Pipeline started: ${data.total} vuln types</span>` })
      if (phases.value.length > 0 && phases.value[0].status === 'pending') {
        phases.value[0].status = 'active'
      }
    },
    intermediate: (data) => {
      if (data.type === 'review_summary') {
        reviewSummary.value = data
      }
      if (data.type === 'pipeline_warnings') {
        pipelineWarnings.value = data.warnings || []
        for (const w of pipelineWarnings.value) {
          addLog({ level: 'warning', message: w, html: `<span class="text-yellow-400 font-bold">⚠ ${w}</span>` })
        }
      }
      if (data.type === 'auto_plan') {
        const types = (data.planned_vuln_types || []).join(', ')
        addLog({ level: 'info', message: `Agent-P 自动规划: ${types}`, html: `<span class="text-argus-purple font-bold">🤖 Agent-P 自动规划漏洞类型: ${types} (${data.rounds || 0} 轮)</span>` })
      }
    },
    complete: (data) => {
      const hasWarnings = data.warnings?.length > 0
      const hasErrors = data.has_errors
      if (hasWarnings) pipelineWarnings.value = data.warnings
      taskStatus.value = hasErrors ? 'completed_with_errors' : hasWarnings ? 'completed_with_warnings' : 'completed'
      resultFile.value = data.result_file || ''
      phases.value.forEach(p => p.status = 'done')
      agentActivity.value.forEach(a => a.active = false)
      if (hasErrors) {
        addLog({ level: 'warning', message: 'Mission complete (with errors)', html: '<span class="text-yellow-400 font-black text-lg">⚠ MISSION COMPLETE (WITH ERRORS)</span>' })
      } else {
        addLog({ level: 'info', message: 'Mission complete!', html: '<span class="text-green-400 font-black text-lg">✓ MISSION COMPLETE</span>' })
      }
      completeTask(data.result_file)
      setTimeout(() => { missionComplete.value = true }, 500)
    },
    error: (data) => {
      const msg = data.message || 'Unknown error'
      if (msg === 'SSE connection lost') return
      taskStatus.value = 'error'
      failTask()
      addLog({ level: 'error', message: msg, html: `<span class="text-red-400 font-bold">ERROR: ${msg}</span>` })
    },
  })
})

onUnmounted(() => { es?.close() })
</script>

<template>
  <div class="h-full w-full flex flex-col overflow-hidden relative">
    <!-- Mission complete overlay -->
    <transition name="page">
      <div v-if="missionComplete" class="absolute inset-0 z-50 bg-black/80 backdrop-blur-md flex flex-col items-center justify-center gap-6">
        <div class="w-20 h-20 rounded-full flex items-center justify-center border-2 shadow-lg"
             :class="pipelineWarnings.length ? 'bg-yellow-500/20 border-yellow-500 shadow-[0_0_40px_rgba(234,179,8,0.3)]' : 'bg-green-500/20 border-green-500 shadow-[0_0_40px_rgba(34,197,94,0.4)]'">
          <AlertTriangle v-if="pipelineWarnings.length" class="w-10 h-10 text-yellow-400" />
          <CheckCircle2 v-else class="w-10 h-10 text-green-400" />
        </div>
        <div class="text-3xl font-black font-mono tracking-[0.4em]" :class="pipelineWarnings.length ? 'text-yellow-400' : 'text-green-400'">
          {{ pipelineWarnings.length ? 'MISSION COMPLETE (WARNINGS)' : 'MISSION COMPLETE' }}
        </div>
        <div v-if="reviewSummary" class="text-sm text-gray-400 font-mono">
          发现 <span class="text-red-400 font-bold text-lg">{{ reviewSummary.vulnerable }}</span> 个漏洞 / {{ reviewSummary.total_findings }} 条告警
        </div>
        <div v-if="pipelineWarnings.length" class="max-w-xl w-full px-4">
          <div v-for="(w, i) in pipelineWarnings" :key="i" class="flex items-start gap-2 px-3 py-2 rounded bg-yellow-500/10 border border-yellow-500/30 mb-2">
            <AlertTriangle class="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
            <span class="text-xs text-yellow-300 font-mono">{{ w }}</span>
          </div>
        </div>
        <div class="flex gap-3 mt-4">
          <button
            v-if="resultFile"
            @click="router.push(`/forensics/${resultFile}`)"
            class="px-6 py-3 rounded-lg bg-argus-purple/20 border border-argus-purple/50 text-white font-mono text-sm font-bold hover:bg-argus-purple/40 transition-all flex items-center gap-2"
          >
            查看证据链 <ArrowRight class="w-4 h-4" />
          </button>
          <button
            @click="missionComplete = false"
            class="px-6 py-3 rounded-lg bg-white/5 border border-white/10 text-gray-400 font-mono text-sm hover:text-white transition-all"
          >
            查看日志
          </button>
        </div>
      </div>
    </transition>

    <!-- Agent Activity Bar -->
    <div class="shrink-0 px-4 pt-4 pb-2">
      <div class="flex items-center gap-2">
        <div
          v-for="a in agentActivity" :key="a.id"
          class="flex items-center gap-2 px-3 py-2 rounded-lg border transition-all text-xs font-mono"
          :class="a.active ? 'border-argus-purple/50 bg-argus-purple/15 text-white' : 'border-white/5 bg-black/20 text-gray-600'"
        >
          <component :is="a.icon" class="w-4 h-4" :class="a.active ? 'text-argus-purple animate-pulse' : ''" />
          <span class="font-bold">{{ a.label }}</span>
        </div>
        <div class="ml-auto flex items-center gap-2 text-[11px] font-mono">
          <div class="w-2 h-2 rounded-full" :class="taskStatus === 'running' ? 'bg-green-400 animate-pulse' : taskStatus.startsWith('completed') ? 'bg-green-400' : 'bg-red-500'"></div>
          <span class="text-gray-500 uppercase">{{ taskStatus === 'completed_with_warnings' ? 'DONE (WARN)' : taskStatus === 'completed_with_errors' ? 'DONE (ERR)' : taskStatus }}</span>
        </div>
      </div>
      <div v-if="agentActivity.find(a => a.active)" class="mt-1.5 text-[10px] text-gray-500 font-mono truncate pl-1">
        {{ agentActivity.find(a => a.active)?.status }}
      </div>
    </div>

    <!-- Main area: Timeline + Log -->
    <div class="flex-1 flex gap-3 px-4 pb-4 min-h-0">
      <!-- Timeline -->
      <div class="w-56 shrink-0 glass-panel p-4 flex flex-col gap-1 overflow-y-auto">
        <div class="text-[10px] font-mono text-gray-500 tracking-wider mb-2">PIPELINE PHASES</div>
        <div v-for="(phase, idx) in phases" :key="phase.key" class="flex items-start gap-3 relative">
          <div class="flex flex-col items-center">
            <div class="w-7 h-7 rounded-full flex items-center justify-center border-2 transition-all shrink-0"
                 :class="{
                   'border-green-500 bg-green-500/20': phase.status === 'done',
                   'border-argus-purple bg-argus-purple/20 animate-pulse': phase.status === 'active',
                   'border-white/10 bg-black/20': phase.status === 'pending',
                 }">
              <CheckCircle2 v-if="phase.status === 'done'" class="w-4 h-4 text-green-400" />
              <Loader2 v-else-if="phase.status === 'active'" class="w-4 h-4 text-argus-purple animate-spin" />
              <Circle v-else class="w-3 h-3 text-gray-600" />
            </div>
            <div v-if="idx < phases.length - 1" class="w-px h-8 transition-colors" :class="phase.status === 'done' ? 'bg-green-500/50' : 'bg-white/5'"></div>
          </div>
          <div class="pt-1">
            <div class="text-[11px] font-mono font-bold" :class="phase.status === 'active' ? 'text-white' : phase.status === 'done' ? 'text-green-400' : 'text-gray-600'">
              {{ phase.label }}
            </div>
          </div>
        </div>

        <!-- Review Summary -->
        <div v-if="reviewSummary" class="mt-auto pt-4 border-t border-white/5">
          <div class="text-[10px] font-mono text-gray-500 mb-1">INTERIM RESULTS</div>
          <div class="text-lg font-black font-mono text-red-400">{{ reviewSummary.vulnerable }}</div>
          <div class="text-[10px] text-gray-500">vulnerabilities / {{ reviewSummary.total_findings }} findings</div>
        </div>
      </div>

      <!-- Terminal Log -->
      <div class="flex-1 glass-panel p-0 flex flex-col overflow-hidden">
        <div class="px-4 py-2 border-b border-white/5 flex items-center gap-2 text-[11px] font-mono text-gray-500 shrink-0">
          <Terminal class="w-3.5 h-3.5 text-green-400" />
          <span>LIVE TERMINAL</span>
          <span class="ml-auto text-gray-600">{{ logs.length }} lines</span>
        </div>
        <div ref="logContainer" class="flex-1 overflow-y-auto p-4 font-mono text-[12px] leading-relaxed bg-black/40 custom-scrollbar">
          <div v-for="(log, i) in logs" :key="i" class="mb-0.5 flex gap-2">
            <span class="text-gray-700 shrink-0 select-none w-8 text-right">{{ i + 1 }}</span>
            <span v-html="log.html" class="break-all"></span>
          </div>
          <div v-if="taskStatus === 'running'" class="text-green-400 animate-pulse mt-1">▊</div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 4px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.2); border-radius: 2px; }
</style>
