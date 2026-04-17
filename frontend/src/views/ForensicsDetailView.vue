<script setup>
import { ref, onMounted, nextTick, computed } from 'vue'
import { useRouter } from 'vue-router'
import {
  ArrowLeft, AlertTriangle, CheckCircle2, AlertCircle, ShieldCheck,
  FileCode, Activity, Terminal, Fingerprint
} from 'lucide-vue-next'
import { fetchResultDetail } from '../api'
import Prism from 'prismjs'
import 'prismjs/components/prism-python'
import 'prismjs/components/prism-javascript'
import 'prismjs/components/prism-java'
import 'prismjs/themes/prism-tomorrow.css'

const props = defineProps({ id: String })
const router = useRouter()

const report = ref(null)
const findings = ref([])
const selectedIdx = ref(0)
const loading = ref(true)
const meta = ref({})

const selected = computed(() => findings.value[selectedIdx.value] || null)

const counters = computed(() => {
  const v = findings.value.filter(f => f.status === 'vulnerable').length
  const s = findings.value.filter(f => f.status === 'safe').length
  const u = findings.value.length - v - s
  return { vulnerable: v, safe: s, uncertain: u }
})

const getStatusIcon = (s) => s === 'vulnerable' ? AlertTriangle : s === 'safe' ? CheckCircle2 : AlertCircle
const getStatusClass = (s) => s === 'vulnerable' ? 'text-red-400' : s === 'safe' ? 'text-green-400' : 'text-yellow-400'
const getStatusBg = (s) => s === 'vulnerable' ? 'bg-red-500/10 border-red-500/20' : s === 'safe' ? 'bg-green-500/10 border-green-500/20' : 'bg-yellow-500/10 border-yellow-500/20'

const getLangClass = (file) => {
  if (!file) return 'language-javascript'
  const ext = file.split('.').pop()
  if (ext === 'py') return 'language-python'
  if (ext === 'java') return 'language-java'
  return 'language-javascript'
}

onMounted(async () => {
  try {
    const data = await fetchResultDetail(props.id)
    report.value = data
    meta.value = data.meta || {}
    let id = 1
    ;(data.runs || []).forEach(run => {
      ;(run.findings || []).forEach(f => {
        let reasoning = []
        if (typeof f.reasoning === 'string') reasoning = f.reasoning.split('\n').filter(Boolean)
        else if (Array.isArray(f.reasoning)) reasoning = f.reasoning
        findings.value.push({
          id: id++,
          status: f.status || 'uncertain',
          file: f.file || 'unknown',
          line: f.line || 0,
          rule_id: f.rule_id || '',
          confidence: f.confidence ? Math.round(f.confidence * 100) : 0,
          code: f.code_context || '',
          reasoning,
          sink_method: f.sink_method || '',
          engine: f.engine || 'codeql',
          poc_result: f.poc_result || f.poc || null,
          vuln_type: run.vuln_type || '',
        })
      })
    })
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
    nextTick(() => Prism.highlightAll())
  }
})

const selectFinding = (idx) => {
  selectedIdx.value = idx
  nextTick(() => Prism.highlightAll())
}
</script>

<template>
  <div class="h-full w-full flex flex-col overflow-hidden">
    <!-- Top bar -->
    <div class="shrink-0 px-5 pt-4 pb-3 flex items-center gap-4 border-b border-white/5">
      <button @click="router.push('/forensics')" class="p-2 rounded-lg hover:bg-white/5 text-gray-500 hover:text-white transition-colors">
        <ArrowLeft class="w-4 h-4" />
      </button>
      <div class="flex-1 min-w-0">
        <div class="text-sm font-mono font-bold text-white truncate">{{ id }}</div>
        <div class="text-[10px] text-gray-500 font-mono">{{ meta.language?.toUpperCase() }} · {{ meta.generated_at }}</div>
      </div>
      <div class="flex items-center gap-4 text-sm font-mono shrink-0">
        <span class="text-red-400 font-bold">{{ counters.vulnerable }} <span class="text-[10px] text-gray-500 font-normal">vuln</span></span>
        <span class="text-green-400 font-bold">{{ counters.safe }} <span class="text-[10px] text-gray-500 font-normal">safe</span></span>
        <span class="text-yellow-400 font-bold">{{ counters.uncertain }} <span class="text-[10px] text-gray-500 font-normal">uncertain</span></span>
      </div>
    </div>

    <div v-if="loading" class="flex-1 flex items-center justify-center text-gray-600 font-mono text-sm">
      <div class="w-5 h-5 rounded-full border-2 border-argus-purple border-t-transparent animate-spin mr-3"></div>
      LOADING EVIDENCE...
    </div>

    <div v-else class="flex-1 flex min-h-0">
      <!-- Finding list -->
      <div class="w-72 shrink-0 border-r border-white/5 overflow-y-auto custom-scrollbar">
        <div
          v-for="(f, idx) in findings" :key="f.id"
          @click="selectFinding(idx)"
          class="px-4 py-3 border-b border-white/5 cursor-pointer transition-all"
          :class="selectedIdx === idx ? 'bg-argus-purple/10 border-l-2 border-l-argus-purple' : 'hover:bg-white/5 border-l-2 border-l-transparent'"
        >
          <div class="flex items-center gap-2 mb-1">
            <component :is="getStatusIcon(f.status)" class="w-3.5 h-3.5 shrink-0" :class="getStatusClass(f.status)" />
            <span class="text-[11px] font-mono text-gray-300 truncate">{{ f.file }}</span>
          </div>
          <div class="flex items-center justify-between text-[10px] font-mono">
            <span class="text-gray-500">L{{ f.line }} · {{ f.vuln_type }}</span>
            <span :class="getStatusClass(f.status)">{{ f.confidence }}%</span>
          </div>
        </div>
        <div v-if="findings.length === 0" class="px-4 py-8 text-center text-gray-600 text-xs font-mono">
          NO FINDINGS
        </div>
      </div>

      <!-- Evidence Chain -->
      <div v-if="selected" class="flex-1 overflow-y-auto p-5 custom-scrollbar">
        <!-- Evidence header -->
        <div class="flex items-center gap-3 mb-5">
          <div class="px-3 py-1 rounded-lg border text-xs font-mono font-bold" :class="getStatusBg(selected.status) + ' ' + getStatusClass(selected.status)">
            {{ selected.status?.toUpperCase() }}
          </div>
          <span class="text-sm font-mono text-white">{{ selected.file }}:{{ selected.line }}</span>
          <span class="text-xs text-gray-500 font-mono">{{ selected.rule_id }}</span>
        </div>

        <!-- Three-level evidence chain -->
        <div class="relative pl-8">
          <div class="absolute left-3 top-0 bottom-0 w-px bg-gradient-to-b from-safe-blue via-argus-purple to-green-500 opacity-30"></div>

          <!-- Level 1: Static Detection -->
          <div class="relative mb-6">
            <div class="absolute -left-5 top-1 w-3 h-3 rounded-full bg-safe-blue/30 border-2 border-safe-blue"></div>
            <div class="glass-panel p-4">
              <div class="flex items-center gap-2 mb-3 text-xs font-mono">
                <Fingerprint class="w-4 h-4 text-safe-blue" />
                <span class="text-safe-blue font-bold tracking-wider">LEVEL 1 — STATIC DETECTION</span>
              </div>
              <div class="text-[11px] font-mono text-gray-400 space-y-1">
                <div>Rule: <span class="text-white">{{ selected.rule_id }}</span></div>
                <div>Vuln Type: <span class="text-white">{{ selected.vuln_type }}</span></div>
                <div>Sink: <span class="text-white">{{ selected.sink_method || '—' }}</span></div>
                <div>Engine: <span class="text-white">{{ selected.engine }}</span></div>
              </div>
              <div v-if="selected.code" class="mt-3 rounded-lg border border-white/5 overflow-hidden bg-[#1d1f21]">
                <div class="px-3 py-1.5 border-b border-white/5 text-[10px] text-gray-500 font-mono bg-black/40">
                  {{ selected.file }}:{{ selected.line }}
                </div>
                <pre class="!m-0 !p-3 !bg-transparent text-[12px] overflow-x-auto"><code :class="getLangClass(selected.file)">{{ selected.code }}</code></pre>
              </div>
            </div>
          </div>

          <!-- Level 2: Semantic Review -->
          <div class="relative mb-6">
            <div class="absolute -left-5 top-1 w-3 h-3 rounded-full bg-argus-purple/30 border-2 border-argus-purple"></div>
            <div class="glass-panel p-4">
              <div class="flex items-center gap-2 mb-3 text-xs font-mono">
                <Activity class="w-4 h-4 text-argus-purple" />
                <span class="text-argus-purple font-bold tracking-wider">LEVEL 2 — SEMANTIC REVIEW</span>
                <span class="ml-auto text-gray-500">Confidence: <span class="text-white">{{ selected.confidence }}%</span></span>
              </div>
              <div class="space-y-1.5 text-[12px] font-mono leading-relaxed">
                <div v-for="(step, i) in selected.reasoning" :key="i" class="flex gap-2">
                  <span class="text-argus-purple shrink-0">❯</span>
                  <span
                    :class="{
                      'text-red-400 font-bold': step.includes('确认漏洞') || step.includes('vulnerable'),
                      'text-green-400 font-bold': step.includes('误报') || step.includes('safe') || step.includes('False Positive'),
                      'text-gray-400 ml-2': step.startsWith('  ') || step.startsWith('-'),
                      'text-gray-300': true,
                    }"
                  >{{ step }}</span>
                </div>
                <div v-if="selected.reasoning.length === 0" class="text-gray-600 italic">No reasoning data available</div>
              </div>
            </div>
          </div>

          <!-- Level 3: Runtime Verification -->
          <div class="relative">
            <div class="absolute -left-5 top-1 w-3 h-3 rounded-full border-2"
                 :class="selected.poc_result ? 'bg-green-500/30 border-green-500' : 'bg-gray-700/30 border-gray-600'"></div>
            <div class="glass-panel p-4">
              <div class="flex items-center gap-2 mb-3 text-xs font-mono">
                <ShieldCheck class="w-4 h-4" :class="selected.poc_result ? 'text-green-400' : 'text-gray-600'" />
                <span class="font-bold tracking-wider" :class="selected.poc_result ? 'text-green-400' : 'text-gray-600'">LEVEL 3 — RUNTIME VERIFICATION</span>
              </div>
              <div v-if="selected.poc_result" class="text-[12px] font-mono text-gray-300 space-y-3">
                <div class="mb-1">Status: <span class="text-green-400 font-bold">CONFIRMED</span></div>
                <template v-if="typeof selected.poc_result === 'object' && selected.poc_result.http_trigger">
                  <div>
                    <span class="text-gray-500 text-[10px]">HTTP TRIGGER</span>
                    <pre class="bg-black/40 rounded-lg p-3 mt-1 border border-white/5 text-[11px] overflow-x-auto whitespace-pre-wrap text-green-300">{{ selected.poc_result.http_trigger.example || `${selected.poc_result.http_trigger.method} ${selected.poc_result.http_trigger.path}` }}</pre>
                  </div>
                  <div v-if="selected.poc_result.payloads && selected.poc_result.payloads.length">
                    <span class="text-gray-500 text-[10px]">PAYLOADS</span>
                    <div class="flex flex-wrap gap-1.5 mt-1">
                      <code v-for="p in selected.poc_result.payloads" :key="p" class="bg-red-500/10 text-red-400 border border-red-500/20 rounded px-2 py-0.5 text-[10px]">{{ p }}</code>
                    </div>
                  </div>
                  <div v-if="selected.poc_result.expected_output">
                    <span class="text-gray-500 text-[10px]">EXPECTED OUTPUT</span>
                    <p class="mt-1 text-[11px] text-gray-400 leading-relaxed">{{ selected.poc_result.expected_output }}</p>
                  </div>
                </template>
                <pre v-else class="bg-black/40 rounded-lg p-3 border border-white/5 text-[11px] overflow-x-auto whitespace-pre-wrap">{{ typeof selected.poc_result === 'string' ? selected.poc_result : JSON.stringify(selected.poc_result, null, 2) }}</pre>
              </div>
              <div v-else class="text-[11px] text-gray-600 font-mono">
                沙箱验证未执行或无数据
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="flex-1 flex items-center justify-center text-gray-600 font-mono text-sm">
        选择左侧发现以查看证据链
      </div>
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 4px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.2); border-radius: 2px; }
</style>
