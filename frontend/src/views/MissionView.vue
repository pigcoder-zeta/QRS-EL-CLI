<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import {
  Crosshair, Rocket, ChevronDown, ChevronUp, Globe, FolderOpen,
  Eye, Code, Terminal, Activity, ShieldCheck, BrainCircuit, Database as DbIcon,
  Scan, Settings2
} from 'lucide-vue-next'
import { fetchVulnCatalog, startScan, fetchScanStatus } from '../api'
import { setActiveTask, scanStore, clearActiveTask } from '../stores/scan'

const router = useRouter()

const inputType = ref('github')
const targetInput = ref('')
const language = ref('java')
const selectedVulnTypes = ref([])
const vulnCatalog = ref([])
const showAdvanced = ref(false)
const isLaunching = ref(false)

const agents = ref({
  agent_t: { enabled: false, label: 'Agent-T', desc: '智能分诊', icon: Eye },
  agent_r: { enabled: true, label: 'Agent-R', desc: '语义审查', icon: Activity },
  agent_s: { enabled: true, label: 'Agent-S', desc: 'PoC 生成', icon: Terminal },
  agent_e: { enabled: true, label: 'Agent-E', desc: '沙箱验证', icon: ShieldCheck },
  rule_memory: { enabled: true, label: 'RAG 知识库', desc: '规则记忆', icon: DbIcon },
  code_browser: { enabled: true, label: 'CodeBrowser', desc: '符号导航', icon: Code },
})

const advancedConfig = ref({
  parallel_workers: 3,
  max_retries: 3,
  min_confidence: 0.6,
  context_lines: 30,
  no_build: false,
  prompt_preset: '',
})

const languages = [
  { value: 'java', label: 'Java' },
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'go', label: 'Go' },
  { value: 'csharp', label: 'C#' },
  { value: 'cpp', label: 'C/C++' },
  { value: 'solidity', label: 'Solidity' },
]

const toggleVuln = (name) => {
  const idx = selectedVulnTypes.value.indexOf(name)
  if (idx >= 0) selectedVulnTypes.value.splice(idx, 1)
  else selectedVulnTypes.value.push(name)
}

const launchMission = async () => {
  if (!targetInput.value) return
  isLaunching.value = true
  try {
    const config = {
      [inputType.value === 'github' ? 'github_url' : 'source_dir']: targetInput.value,
      language: language.value,
      vuln_types: selectedVulnTypes.value.length ? selectedVulnTypes.value : undefined,
      enable_agent_r: agents.value.agent_r.enabled,
      enable_agent_t: agents.value.agent_t.enabled,
      enable_agent_s: agents.value.agent_s.enabled,
      enable_agent_e: agents.value.agent_e.enabled,
      enable_rule_memory: agents.value.rule_memory.enabled,
      enable_code_browser: agents.value.code_browser.enabled,
      ...advancedConfig.value,
    }
    const { task_id } = await startScan(config)
    setActiveTask(task_id)
    router.push(`/mission/${task_id}`)
  } catch (e) {
    console.error(e)
    isLaunching.value = false
  }
}

onMounted(async () => {
  if (scanStore.activeTaskId && scanStore.status === 'running') {
    try {
      const status = await fetchScanStatus(scanStore.activeTaskId)
      if (status?.status === 'running' || status?.status === 'pending') {
        router.replace(`/mission/${scanStore.activeTaskId}`)
        return
      }
      if (status?.status === 'completed' || status?.status === 'error') {
        clearActiveTask()
      }
    } catch {
      // API 不可达时仍然尝试跳转
      router.replace(`/mission/${scanStore.activeTaskId}`)
      return
    }
  }
  try {
    vulnCatalog.value = await fetchVulnCatalog()
  } catch {}
})
</script>

<template>
  <div class="h-full w-full flex flex-col overflow-hidden">
    <!-- Header -->
    <div class="shrink-0 px-6 pt-5 pb-4 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-argus-purple/15 flex items-center justify-center border border-argus-purple/30">
          <Crosshair class="w-5 h-5 text-argus-purple" />
        </div>
        <div>
          <h2 class="text-lg font-bold text-white tracking-wide font-mono">MISSION CONTROL</h2>
          <p class="text-[11px] text-gray-500 font-mono">配置并启动扫描任务</p>
        </div>
      </div>
    </div>

    <!-- Content -->
    <div class="flex-1 overflow-y-auto px-6 pb-6 custom-scrollbar">
      <div class="max-w-3xl mx-auto space-y-5">

        <!-- Target Input -->
        <div class="glass-panel p-5">
          <div class="text-xs font-mono text-gray-400 mb-3 tracking-wider">TARGET ACQUISITION</div>
          <div class="flex gap-2 mb-3">
            <button
              @click="inputType = 'github'"
              class="px-4 py-2 rounded-lg text-xs font-mono font-bold flex items-center gap-2 transition-all border"
              :class="inputType === 'github' ? 'border-argus-purple/50 bg-argus-purple/15 text-white' : 'border-white/5 text-gray-500 hover:text-gray-300'"
            >
              <Globe class="w-4 h-4" /> GITHUB
            </button>
            <button
              @click="inputType = 'local'"
              class="px-4 py-2 rounded-lg text-xs font-mono font-bold flex items-center gap-2 transition-all border"
              :class="inputType === 'local' ? 'border-safe-blue/50 bg-safe-blue/15 text-white' : 'border-white/5 text-gray-500 hover:text-gray-300'"
            >
              <FolderOpen class="w-4 h-4" /> LOCAL PATH
            </button>
          </div>
          <input
            v-model="targetInput"
            type="text"
            class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-3 text-sm text-white font-mono placeholder-gray-600 focus:outline-none focus:border-argus-purple/50 transition-all"
            :placeholder="inputType === 'github' ? 'https://github.com/owner/repo' : 'C:\\path\\to\\project'"
          />
        </div>

        <!-- Language -->
        <div class="glass-panel p-5">
          <div class="text-xs font-mono text-gray-400 mb-3 tracking-wider">LANGUAGE</div>
          <div class="flex flex-wrap gap-2">
            <button
              v-for="lang in languages" :key="lang.value"
              @click="language = lang.value"
              class="px-4 py-2 rounded-lg text-xs font-mono font-bold transition-all border"
              :class="language === lang.value ? 'border-safe-blue/50 bg-safe-blue/15 text-white' : 'border-white/5 text-gray-500 hover:text-gray-300 hover:bg-white/5'"
            >
              {{ lang.label }}
            </button>
          </div>
        </div>

        <!-- Vuln Types -->
        <div class="glass-panel p-5">
          <div class="text-xs font-mono text-gray-400 mb-1 tracking-wider">VULN TYPES</div>
          <div class="text-[10px] text-gray-600 mb-3">留空则使用 Agent-P 自动规划</div>
          <div class="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto custom-scrollbar">
            <button
              v-for="v in vulnCatalog" :key="v.name"
              @click="toggleVuln(v.name)"
              class="px-3 py-1.5 rounded-md text-[11px] font-mono transition-all border"
              :class="selectedVulnTypes.includes(v.name)
                ? 'border-red-500/50 bg-red-500/15 text-red-300'
                : 'border-white/5 text-gray-500 hover:text-gray-300 hover:bg-white/5'"
              :title="v.description"
            >
              {{ v.name }}
            </button>
          </div>
        </div>

        <!-- Agent Matrix -->
        <div class="glass-panel p-5">
          <div class="text-xs font-mono text-gray-400 mb-3 tracking-wider">AGENT MATRIX</div>
          <div class="grid grid-cols-3 gap-2">
            <button
              v-for="(a, key) in agents" :key="key"
              @click="a.enabled = !a.enabled"
              class="flex items-center gap-2 px-3 py-2.5 rounded-lg border transition-all text-left"
              :class="a.enabled
                ? 'border-argus-purple/40 bg-argus-purple/10 text-white'
                : 'border-white/5 text-gray-600 hover:bg-white/5'"
            >
              <component :is="a.icon" class="w-4 h-4 shrink-0" />
              <div class="min-w-0">
                <div class="text-[11px] font-mono font-bold truncate">{{ a.label }}</div>
                <div class="text-[9px] text-gray-500 truncate">{{ a.desc }}</div>
              </div>
              <div class="ml-auto w-2 h-2 rounded-full shrink-0" :class="a.enabled ? 'bg-green-400 shadow-[0_0_6px_rgba(74,222,128,0.6)]' : 'bg-gray-700'"></div>
            </button>
          </div>
        </div>

        <!-- Advanced -->
        <div class="glass-panel overflow-hidden">
          <button
            @click="showAdvanced = !showAdvanced"
            class="w-full px-5 py-3 flex items-center justify-between text-xs font-mono text-gray-400 hover:text-gray-300 transition-colors"
          >
            <div class="flex items-center gap-2">
              <Settings2 class="w-4 h-4" />
              <span class="tracking-wider">ADVANCED CONFIG</span>
            </div>
            <ChevronDown v-if="!showAdvanced" class="w-4 h-4" />
            <ChevronUp v-else class="w-4 h-4" />
          </button>
          <div v-if="showAdvanced" class="px-5 pb-4 grid grid-cols-2 gap-3">
            <label class="flex flex-col gap-1">
              <span class="text-[10px] text-gray-500 font-mono">并行 Workers</span>
              <input v-model.number="advancedConfig.parallel_workers" type="number" min="1" max="8" class="bg-black/30 border border-white/10 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-argus-purple/50" />
            </label>
            <label class="flex flex-col gap-1">
              <span class="text-[10px] text-gray-500 font-mono">最大重试</span>
              <input v-model.number="advancedConfig.max_retries" type="number" min="1" max="5" class="bg-black/30 border border-white/10 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-argus-purple/50" />
            </label>
            <label class="flex flex-col gap-1">
              <span class="text-[10px] text-gray-500 font-mono">最小置信度</span>
              <input v-model.number="advancedConfig.min_confidence" type="number" min="0" max="1" step="0.1" class="bg-black/30 border border-white/10 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-argus-purple/50" />
            </label>
            <label class="flex flex-col gap-1">
              <span class="text-[10px] text-gray-500 font-mono">上下文行数</span>
              <input v-model.number="advancedConfig.context_lines" type="number" min="5" max="100" class="bg-black/30 border border-white/10 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-argus-purple/50" />
            </label>
            <label class="col-span-2 flex items-center gap-2 cursor-pointer">
              <input v-model="advancedConfig.no_build" type="checkbox" class="accent-argus-purple" />
              <span class="text-[10px] text-gray-500 font-mono">跳过编译（source extraction mode）</span>
            </label>
          </div>
        </div>

        <!-- Launch -->
        <button
          @click="launchMission"
          :disabled="!targetInput || isLaunching"
          class="w-full py-4 rounded-xl font-black tracking-[0.3em] text-sm font-mono border-2 transition-all flex items-center justify-center gap-3"
          :class="!targetInput || isLaunching
            ? 'border-gray-700 bg-gray-800/30 text-gray-600 cursor-not-allowed'
            : 'border-argus-purple bg-argus-purple/20 text-white hover:bg-argus-purple hover:shadow-[0_0_30px_rgba(139,92,246,0.5)] cursor-pointer'"
        >
          <Rocket v-if="!isLaunching" class="w-5 h-5" />
          <div v-else class="w-5 h-5 rounded-full border-2 border-white border-t-transparent animate-spin"></div>
          {{ isLaunching ? 'LAUNCHING...' : 'LAUNCH MISSION' }}
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 4px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.2); border-radius: 2px; }
</style>
