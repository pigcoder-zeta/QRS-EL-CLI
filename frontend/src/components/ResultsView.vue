<script setup>
import { ref, onMounted, nextTick } from 'vue'
import { CheckCircle2, AlertTriangle, AlertCircle, ServerCrash, Bug, ShieldCheck, Zap } from 'lucide-vue-next'
import Prism from 'prismjs'
import 'prismjs/components/prism-python'
import 'prismjs/components/prism-javascript'
import 'prismjs/components/prism-java'
import 'prismjs/themes/prism-tomorrow.css'

const metrics = ref([
  { label: '精确率 (Precision)', value: '...', change: '', color: 'text-safe-blue', icon: ShieldCheck },
  { label: '误报率 (FPR)', value: '...', change: '', color: 'text-argus-purple', icon: ServerCrash },
  { label: 'F1 分数', value: '...', change: '', color: 'text-neon-blue', icon: Zap },
])

const findings = ref([])
const loading = ref(true)

const playSound = (name, volume = 0.2) => {
  const audio = new Audio(`/sounds/${name}.wav`)
  audio.volume = volume
  audio.play().catch(e => console.warn('Audio play prevented:', e))
}

const fetchMetrics = async () => {
  try {
    const res = await fetch('/api/benchmark/scores')
    if (res.ok) {
      const data = await res.json()
      if (data && data.length > 0) {
        const latest = data[data.length - 1]
        if (latest.overall) {
          metrics.value[0].value = (latest.overall.precision * 100).toFixed(1) + '%'
          metrics.value[1].value = (latest.overall.fpr * 100).toFixed(1) + '%'
          metrics.value[2].value = (latest.overall.f1).toFixed(3)
          metrics.value[0].change = 'Real Data'
          metrics.value[1].change = 'Real Data'
          metrics.value[2].change = 'Real Data'
        }
      }
    }
  } catch (e) {
    console.warn("Failed to fetch benchmark scores", e)
  }
}

const fetchFindings = async () => {
  try {
    const listRes = await fetch('/api/results')
    if (!listRes.ok) return
    const listData = await listRes.json()
    if (!listData || listData.length === 0) {
      loading.value = false
      return
    }

    // Get the latest result
    const latestFile = listData[0].filename
    const detailRes = await fetch(`/api/results/${latestFile}`)
    if (!detailRes.ok) return
    const detailData = await detailRes.json()
    
    let allFindings = []
    let idCounter = 1
    ;(detailData.runs || []).forEach(run => {
      ;(run.findings || []).forEach(f => {
        let reasoningList = []
        if (typeof f.reasoning === 'string') {
          reasoningList = f.reasoning.split('\n')
        } else if (Array.isArray(f.reasoning)) {
          reasoningList = f.reasoning
        } else {
          reasoningList = ["[Agent-R] 审查信息暂无"]
        }
        
        allFindings.push({
          id: idCounter++,
          status: f.status || 'uncertain',
          file: f.file || 'unknown',
          line: f.line || 0,
          rule: f.rule_id || 'unknown-rule',
          confidence: f.confidence ? Math.round(f.confidence * 100) : 0,
          code: f.code_context || '// Code missing',
          reasoning: reasoningList,
          expanded: false
        })
      })
    })

    // If no real findings, fallback to mock data
    if (allFindings.length === 0) {
      allFindings = getMockFindings()
    }

    findings.value = allFindings
    if (allFindings.length > 0) {
      allFindings[0].expanded = true
    }
  } catch (e) {
    console.warn("Failed to fetch real findings, using mock", e)
    findings.value = getMockFindings()
  } finally {
    loading.value = false
    nextTick(() => {
      Prism.highlightAll()
    })
  }
}

onMounted(() => {
  fetchMetrics()
  fetchFindings()
})

const toggleExpand = (finding) => {
  playSound('scan', 0.2)
  findings.value.forEach(f => f.expanded = false)
  finding.expanded = true
  nextTick(() => Prism.highlightAll())
}

const getStatusIcon = (status) => {
  if (status === 'vulnerable') return AlertTriangle
  if (status === 'safe') return CheckCircle2
  return AlertCircle
}

const getStatusColor = (status) => {
  if (status === 'vulnerable') return 'text-red-400 bg-red-400/10 border-red-400/30'
  if (status === 'safe') return 'text-green-400 bg-green-400/10 border-green-400/30'
  return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
}

const getMockFindings = () => [
  {
    id: 1, status: 'vulnerable', file: 'src/api/auth.py', line: 42, rule: 'sql-injection', confidence: 96,
    code: `def get_user(username):\n    query = "SELECT * FROM users WHERE name = '" + username + "'"\n    return db.execute(query)`,
    reasoning: [
      "[CodeQL] 检测到潜在的 SQL 注入风险，从参数 `username` 到 `db.execute`。",
      "[Agent-T] 触发高危规则分诊，移交 Agent-R。",
      "[Agent-R] 语义审查开始...",
      "  - 追踪 `username` 来源：直接来自 API 路由参数，未经过滤。",
      "  - 分析 `db.execute` 上下文：使用字符串拼接构建 SQL 语句。",
      "  - 结论：确认漏洞。用户输入直接拼接到 SQL 语句中，导致注入风险。"
    ],
    expanded: true
  },
  {
    id: 2, status: 'safe', file: 'src/utils/sanitizer.js', line: 15, rule: 'xss-vulnerability', confidence: 99,
    code: `function renderHtml(input) {\n    const safeInput = DOMPurify.sanitize(input);\n    document.getElementById('content').innerHTML = safeInput;\n}`,
    reasoning: [
      "[CodeQL] 检测到 DOM XSS，从 `input` 到 `innerHTML`。",
      "[Agent-R] 审查上下文...",
      "  - 发现 `DOMPurify.sanitize(input)` 过滤操作。",
      "  - 结论：误报 (False Positive)。数据流在到达 sink 前已被安全处理。"
    ],
    expanded: false
  }
]
</script>

<template>
  <div class="h-full flex flex-col gap-6">
    <!-- Top Metrics Dashboards -->
    <div class="grid grid-cols-3 gap-6 shrink-0">
      <div 
        v-for="(metric, idx) in metrics" 
        :key="idx"
        class="cyber-card flex items-center justify-between group clickable"
        @click="playSound('click', 0.2)"
      >
        <!-- Hover glow background -->
        <div class="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
        
        <div class="relative z-10">
          <p class="text-gray-400 text-sm font-medium mb-1">{{ metric.label }}</p>
          <div class="flex items-baseline gap-3">
            <span class="text-3xl font-bold font-mono tracking-tight" :class="metric.color">
              {{ metric.value }}
            </span>
            <span v-if="metric.change" class="text-xs font-mono" :class="metric.change.includes('-') ? 'text-red-400' : 'text-green-400'">
              {{ metric.change }}
            </span>
          </div>
        </div>
        
        <div class="relative z-10 w-12 h-12 rounded-full flex items-center justify-center border border-white/10 bg-black/20">
          <component :is="metric.icon" class="w-6 h-6" :class="metric.color" />
        </div>
      </div>
    </div>

    <!-- Main Content: Real-time Stream & CoT -->
    <div class="flex-1 flex gap-6 min-h-0">
      
      <!-- Findings List -->
      <div class="w-1/3 flex flex-col cyber-card p-0 overflow-hidden">
        <div class="p-4 border-b border-white/10 bg-black/20 shrink-0 flex items-center justify-between">
           <h3 class="font-bold text-gray-200 tracking-wider flex items-center gap-2">
               <Bug class="w-4 h-4 text-neon-blue" />
               实时扫描流
           </h3>
           <div class="flex items-center gap-2">
               <span class="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
               <span class="text-xs text-gray-500 font-mono">{{ loading ? 'LOADING...' : 'LISTENING...' }}</span>
           </div>
        </div>
        
        <div class="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
          <div v-if="loading" class="text-center text-gray-500 text-sm py-10">获取真实扫描数据中...</div>
          <div 
            v-else
            v-for="f in findings" 
            :key="f.id"
            class="p-3 rounded-lg border cursor-pointer transition-all duration-200 clickable"
            :class="f.expanded ? 'bg-white/5 border-argus-purple/50 shadow-[0_0_15px_rgba(139,92,246,0.1)]' : 'bg-black/20 border-white/5 hover:border-white/20'"
            @click="toggleExpand(f)"
          >
            <div class="flex items-start justify-between mb-2">
              <div class="flex items-center gap-2 max-w-[80%]">
                 <component :is="getStatusIcon(f.status)" class="w-4 h-4 shrink-0" :class="getStatusColor(f.status).split(' ')[0]" />
                 <span class="text-sm font-mono text-gray-300 truncate" :title="f.file">{{ f.file }}:{{ f.line }}</span>
              </div>
              <div class="px-2 py-0.5 rounded text-[10px] font-bold tracking-wide uppercase border" :class="getStatusColor(f.status)">
                {{ f.status === 'vulnerable' ? '漏洞' : f.status === 'safe' ? '安全' : '待定' }}
              </div>
            </div>
            
            <div class="flex items-center justify-between text-xs">
               <span class="text-gray-500 font-mono truncate max-w-[150px]">{{ f.rule }}</span>
               <span class="text-gray-400 shrink-0">
                   置信度: <span :class="f.confidence > 90 ? 'text-green-400' : 'text-yellow-400'">{{ f.confidence }}%</span>
               </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Detail View (CoT & Code) -->
      <div class="flex-1 cyber-card flex flex-col overflow-hidden p-0 relative">
        <template v-if="findings.find(f => f.expanded)">
            <div class="p-4 border-b border-white/10 bg-black/20 shrink-0 flex items-center justify-between z-10">
               <h3 class="font-bold text-gray-200 tracking-wider">深度溯源路径 (Agent-R)</h3>
               <div class="px-3 py-1 rounded bg-argus-purple/20 border border-argus-purple/30 text-argus-purple text-xs font-mono flex items-center gap-2">
                   <div class="w-1.5 h-1.5 rounded-full bg-argus-purple animate-pulse"></div>
                   Semantic Review Active
               </div>
            </div>

            <div class="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar">
                <div v-for="f in findings.filter(f => f.expanded)" :key="f.id">
                   
                   <!-- Code View -->
                   <div class="rounded-xl border border-white/10 overflow-hidden mb-6 bg-[#1d1f21]">
                       <div class="flex items-center px-4 py-2 bg-black/40 border-b border-white/5 text-xs text-gray-500 font-mono">
                           {{ f.file }}
                       </div>
                       <pre class="!m-0 !p-4 !bg-transparent text-sm max-h-[300px] overflow-auto"><code :class="`language-${f.file.split('.').pop() === 'py' ? 'python' : f.file.split('.').pop() === 'js' ? 'javascript' : 'java'}`">{{ f.code }}</code></pre>
                   </div>

                   <!-- Chain of Thought (Typewriter effect simulated) -->
                   <div class="space-y-3">
                       <h4 class="text-sm font-bold text-neon-blue font-mono mb-4 flex items-center gap-2">
                           <TerminalSquare class="w-4 h-4" />
                           Chain-of-Thought (推导链)
                       </h4>
                       
                       <div 
                         v-for="(step, i) in f.reasoning" 
                         :key="i"
                         class="flex gap-3 text-sm font-mono leading-relaxed"
                       >
                           <span class="text-argus-purple shrink-0 mt-0.5">❯</span>
                           <span 
                             class="text-gray-300"
                             :class="{
                               'text-red-400': step.includes('结论：确认漏洞') || step.includes('vulnerable'),
                               'text-green-400': step.includes('结论：误报') || step.includes('safe'),
                               'text-yellow-400': step.includes('建议：需要 Agent-E') || step.includes('uncertain'),
                               'ml-4 text-gray-400': step.startsWith('  -') || step.startsWith(' ') || step.startsWith('-')
                             }"
                           >
                               {{ step }}
                           </span>
                       </div>
                       <div class="flex gap-3 mt-4 text-sm font-mono animate-pulse">
                           <span class="text-argus-purple shrink-0 mt-0.5">❯</span>
                           <span class="text-neon-blue">_</span>
                       </div>
                   </div>
                </div>
            </div>
            
            <!-- Bottom glow -->
            <div class="absolute bottom-0 left-0 right-0 h-24 bg-gradient-to-t from-cyber-base to-transparent pointer-events-none"></div>
        </template>
        <div v-else class="flex-1 flex flex-col items-center justify-center text-gray-600">
            <ShieldCheck class="w-16 h-16 mb-4 opacity-50" />
            <p>请在左侧选择一个发现以查看深度分析</p>
        </div>
      </div>

    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: rgba(0, 0, 0, 0.2);
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 3px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(139, 92, 246, 0.5);
}
</style>
