<script setup>
import { ref, onMounted, nextTick, onUnmounted } from 'vue'
import { ServerCrash, AlertTriangle, ShieldCheck, TerminalSquare, Activity, ChevronDown, ChevronUp } from 'lucide-vue-next'
import Prism from 'prismjs'

const emit = defineEmits(['trace-alert'])

const metrics = ref({ precision: '...', fpr: '34.9%', f1: '...' })
const fprAnimation = ref(false)
const isExpanded = ref(true)

const toggleExpand = () => {
    isExpanded.value = !isExpanded.value
}

const latestRawAlerts = ref([])
const latestCoT = ref([])
const verifiedStatus = ref('uncertain')

let simulationInterval = null
const mockVulnerabilities = [
    { rule: 'Path Traversal', file: 'api.js', line: 124, msg: 'Unsanitized input in path resolution.' },
    { rule: 'XSS', file: 'User.jsx', line: 42, msg: 'Direct assignment to innerHTML.' },
    { rule: 'SQL Injection', file: 'query.py', line: 88, msg: 'String formatting in SQL execute.' },
    { rule: 'Insecure Crypto', file: 'token.go', line: 15, msg: 'Use of weak hashing algorithm.' }
]
let mockIndex = 0

const runSimulation = () => {
    // 1. New CodeQL Alert arrives
    const vuln = mockVulnerabilities[mockIndex % mockVulnerabilities.length]
    mockIndex++
    
    latestRawAlerts.value.unshift({
        id: Date.now(),
        ...vuln,
        code: `// [CodeQL] ${vuln.rule} found at ${vuln.file}:${vuln.line}\n// ${vuln.msg}`
    })
    
    if (latestRawAlerts.value.length > 5) {
        latestRawAlerts.value.pop()
    }
    nextTick(() => Prism.highlightAll())

    // 2. Clear CoT and start reasoning
    latestCoT.value = []
    verifiedStatus.value = 'uncertain'
    metrics.value.fpr = '34.9%'
    
    setTimeout(() => pushCot(`[Agent-R] Intercepted CodeQL alert: ${vuln.rule}`), 200)
    setTimeout(() => pushCot(`  - Extracting AST from ${vuln.file}:${vuln.line}...`), 600)
    setTimeout(() => pushCot(`  - Checking data flow sanitizers...`), 1200)
    setTimeout(() => pushCot(`  - 正在分析 Sanitizer 逻辑...`), 1800)
    
    setTimeout(() => {
        const isFalsePositive = Math.random() > 0.4
        if (isFalsePositive) {
            pushCot(`  - Found active sanitizer before sink!`)
            pushCot(`  - 结论：确认为误报 (False Positive)。`)
            verifiedStatus.value = 'safe'
            triggerFprDrop('10.0%')
        } else {
            pushCot(`  - 确认风险不可忽略。Data flows directly to sensitive sink.`)
            pushCot(`  - 结论：确认漏洞 (True Positive)。`)
            verifiedStatus.value = 'vulnerable'
        }
    }, 2500)
}

const pushCot = (text) => {
    latestCoT.value.push(text)
}

const triggerFprDrop = (newValue) => {
    fprAnimation.value = true
    metrics.value.fpr = newValue
    setTimeout(() => fprAnimation.value = false, 1000)
}

onMounted(() => {
  runSimulation()
  simulationInterval = setInterval(runSimulation, 3000)
})

onUnmounted(() => {
    clearInterval(simulationInterval)
})
</script>

<template>
  <div class="flex flex-col bg-cyber-base/80 transition-all duration-500 w-full" :class="isExpanded ? 'h-full p-4' : 'h-14 p-0 border-t border-white/5'">
    <div class="flex items-center justify-between shrink-0 cursor-pointer hover:bg-white/5 transition-colors group"
         :class="isExpanded ? 'border-b border-white/5 pb-3 mb-4' : 'h-14 px-4'"
         @click="toggleExpand">
        <div class="flex items-center gap-3">
            <button class="text-gray-500 group-hover:text-white transition-colors">
                <ChevronDown v-if="isExpanded" class="w-5 h-5" />
                <ChevronUp v-else class="w-5 h-5" />
            </button>
            <h3 class="font-bold text-gray-200 tracking-wider flex items-center gap-2 font-mono">
                <ShieldCheck class="w-5 h-5" :class="isExpanded ? 'text-safe-blue' : 'text-gray-400 group-hover:text-safe-blue transition-colors'" />
                双重验证对比 (Dual Validation)
            </h3>
        </div>
        <div class="flex items-center gap-6">
            <div class="flex items-center gap-2">
                <span class="text-xs text-gray-500">初始误报率 (FPR):</span>
                <span class="text-sm text-red-400 line-through font-mono">34.9%</span>
            </div>
            <div class="flex items-center gap-2">
                <span class="text-xs text-gray-500">Agent-R 介入后 FPR:</span>
                <span class="text-sm font-bold font-mono transition-colors duration-300"
                      :class="fprAnimation ? 'text-green-300 scale-125' : 'text-green-400'">
                      {{ metrics.fpr }}
                </span>
            </div>
        </div>
    </div>

    <div v-show="isExpanded" class="flex-1 flex gap-6 min-h-0 font-mono transition-all duration-500 animate-[fadeIn_0.5s_ease-out]">
        <!-- Left: CodeQL Raw -->
        <div class="w-1/2 flex flex-col border border-white/10 rounded-xl bg-cyber-dark/80 backdrop-blur-md overflow-hidden relative shadow-lg">
            <div class="p-2 border-b border-white/10 bg-gradient-to-r from-red-500/20 to-transparent flex items-center justify-between">
                <div class="flex items-center gap-2 text-xs text-red-400 font-bold">
                    <AlertTriangle class="w-4 h-4" /> CodeQL 原始告警流
                </div>
                <div class="text-[10px] text-red-500/70 tracking-widest">STATIC.STREAM</div>
            </div>
            <div class="p-4 flex-1 overflow-y-auto custom-scrollbar flex flex-col gap-3">
                <div v-for="(alert, idx) in latestRawAlerts" :key="alert.id"
                     class="border border-white/5 rounded bg-black/40 p-3 transition-all"
                     :class="idx === 0 ? 'border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.1)]' : 'opacity-50'">
                    <div class="flex justify-between items-center text-xs mb-2">
                        <span class="text-red-400 font-bold">[{{ alert.rule }}]</span>
                        <span class="text-gray-500">{{ alert.file }}:{{ alert.line }}</span>
                    </div>
                    <div class="text-sm text-gray-300 mb-2">{{ alert.msg }}</div>
                    <pre v-if="idx===0" class="!m-0 !p-2 !bg-black text-xs border border-white/5 rounded"><code class="language-javascript">{{ alert.code }}</code></pre>
                </div>
            </div>
        </div>

        <!-- Right: Agent-R CoT -->
        <div class="w-1/2 flex flex-col border border-white/10 rounded-xl bg-cyber-dark/80 backdrop-blur-md overflow-hidden relative shadow-lg">
            <div class="p-2 border-b border-white/10 bg-gradient-to-r from-argus-purple/20 to-transparent flex items-center justify-between">
                <div class="flex items-center gap-2 text-xs text-argus-purple font-bold">
                    <TerminalSquare class="w-4 h-4" /> Agent-R 审查思维链 (CoT)
                </div>
                <div class="flex gap-2 items-center">
                    <button 
                        @click="emit('trace-alert')"
                        class="px-2 py-0.5 rounded bg-argus-purple/20 border border-argus-purple/30 text-argus-purple text-[10px] hover:bg-argus-purple/40 hover:text-white transition-colors clickable flex items-center gap-1 font-bold tracking-wider"
                    >
                        <Activity class="w-3 h-3" /> TRACE PATH
                    </button>
                    <div class="w-1.5 h-1.5 bg-argus-purple rounded-full animate-ping ml-2"></div>
                    <div class="text-[10px] text-argus-purple tracking-widest">ANALYZING</div>
                </div>
            </div>
            <div class="p-5 flex-1 overflow-y-auto custom-scrollbar space-y-4 text-sm leading-relaxed" v-if="latestCoT.length">
                <div 
                    v-for="(step, i) in latestCoT" 
                    :key="i"
                    class="flex gap-3"
                    style="animation: slideIn 0.3s ease forwards"
                >
                    <span class="text-argus-purple shrink-0 mt-0.5">❯</span>
                    <span 
                        class="text-gray-300"
                        :class="{
                        'text-red-400 font-bold': step.includes('确认漏洞'),
                        'text-green-400 font-bold': step.includes('误报'),
                        'ml-4 text-gray-400': step.startsWith('  -') || step.startsWith(' ') || step.startsWith('-')
                        }"
                    >
                        {{ step }}
                    </span>
                </div>
                <div v-if="verifiedStatus === 'uncertain'" class="flex gap-3 mt-2 text-sm animate-pulse">
                    <span class="text-argus-purple shrink-0">❯</span>
                    <span class="text-neon-blue">_</span>
                </div>
            </div>
            
            <!-- Verification Stamp -->
            <div v-if="verifiedStatus !== 'uncertain'" class="absolute bottom-6 right-6 rotate-[-15deg] opacity-80 pointer-events-none" style="animation: stampIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;">
                <div class="px-5 py-2 border-4 font-black text-2xl tracking-widest uppercase rounded-xl backdrop-blur-sm"
                     :class="verifiedStatus === 'vulnerable' ? 'text-red-500 border-red-500 bg-red-500/10 shadow-[0_0_20px_rgba(239,68,68,0.5)]' : 'text-green-500 border-green-500 bg-green-500/10 shadow-[0_0_20px_rgba(34,197,94,0.5)]'">
                    {{ verifiedStatus === 'vulnerable' ? 'TRUE POSITIVE' : 'FALSE POSITIVE' }}
                </div>
            </div>
        </div>
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 6px; }
.custom-scrollbar::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.2); }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.3); border-radius: 3px; }
.custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(139, 92, 246, 0.6); }

@keyframes slideIn {
    from { opacity: 0; transform: translateX(10px); }
    to { opacity: 1; transform: translateX(0); }
}

@keyframes stampIn {
    0% { opacity: 0; transform: scale(2) rotate(-15deg); }
    100% { opacity: 1; transform: scale(1) rotate(-15deg); }
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}
</style>

