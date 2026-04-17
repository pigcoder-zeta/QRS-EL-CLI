<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { FlaskConical, AlertTriangle, ShieldCheck, Clock, Code, Filter } from 'lucide-vue-next'
import { fetchResults } from '../api'

const router = useRouter()
const results = ref([])
const loading = ref(true)
const filterLang = ref('')

const filtered = computed(() => {
  if (!filterLang.value) return results.value
  return results.value.filter(r => r.language === filterLang.value)
})

const allLanguages = computed(() => [...new Set(results.value.map(r => r.language).filter(Boolean))])

const getStatusColor = (r) => {
  if (r.total_vulnerabilities > 0) return 'border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.1)]'
  return 'border-green-500/20'
}

const formatTime = (t) => {
  if (!t) return '—'
  try {
    const d = new Date(t)
    return d.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
  } catch { return t }
}

onMounted(async () => {
  try {
    results.value = await fetchResults()
  } catch {} finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="h-full w-full flex flex-col overflow-hidden">
    <!-- Header -->
    <div class="shrink-0 px-6 pt-5 pb-4 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-safe-blue/15 flex items-center justify-center border border-safe-blue/30">
          <FlaskConical class="w-5 h-5 text-safe-blue" />
        </div>
        <div>
          <h2 class="text-lg font-bold text-white tracking-wide font-mono">FORENSICS LAB</h2>
          <p class="text-[11px] text-gray-500 font-mono">案件档案 · 证据链深度分析</p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <Filter class="w-4 h-4 text-gray-500" />
        <select
          v-model="filterLang"
          class="bg-black/30 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-gray-300 font-mono focus:outline-none focus:border-argus-purple/50"
        >
          <option value="">ALL LANGS</option>
          <option v-for="l in allLanguages" :key="l" :value="l">{{ l?.toUpperCase() }}</option>
        </select>
      </div>
    </div>

    <!-- Cases Grid -->
    <div class="flex-1 overflow-y-auto px-6 pb-6 custom-scrollbar">
      <div v-if="loading" class="flex items-center justify-center h-full text-gray-600 font-mono text-sm">
        <div class="w-5 h-5 rounded-full border-2 border-argus-purple border-t-transparent animate-spin mr-3"></div>
        LOADING CASE FILES...
      </div>
      <div v-else-if="filtered.length === 0" class="flex flex-col items-center justify-center h-full text-gray-600">
        <FlaskConical class="w-16 h-16 mb-4 opacity-30" />
        <p class="font-mono text-sm">暂无扫描记录</p>
        <button @click="router.push('/mission')" class="mt-4 px-4 py-2 rounded-lg border border-argus-purple/30 text-argus-purple text-xs font-mono hover:bg-argus-purple/10 transition-all">
          前往 MISSION CONTROL →
        </button>
      </div>
      <div v-else class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        <div
          v-for="r in filtered" :key="r.filename"
          @click="router.push(`/forensics/${r.filename}`)"
          class="glass-panel p-5 cursor-pointer transition-all hover:scale-[1.02] hover:border-argus-purple/30 group border"
          :class="getStatusColor(r)"
        >
          <!-- Status indicator -->
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2">
              <div class="w-2.5 h-2.5 rounded-full" :class="r.total_vulnerabilities > 0 ? 'bg-red-500 animate-pulse' : 'bg-green-500'"></div>
              <span class="text-xs font-mono font-bold text-white uppercase">{{ r.language || 'unknown' }}</span>
            </div>
            <div class="flex items-center gap-1 text-[10px] text-gray-500 font-mono">
              <Clock class="w-3 h-3" />
              {{ formatTime(r.generated_at) }}
            </div>
          </div>

          <!-- Vuln count -->
          <div class="mb-3">
            <span class="text-3xl font-black font-mono" :class="r.total_vulnerabilities > 0 ? 'text-red-400' : 'text-green-400'">
              {{ r.total_vulnerabilities }}
            </span>
            <span class="text-xs text-gray-500 ml-2">vulnerabilities</span>
          </div>

          <!-- Vuln type tags -->
          <div class="flex flex-wrap gap-1 mb-3">
            <span
              v-for="vt in r.vuln_types?.slice(0, 4)" :key="vt"
              class="px-2 py-0.5 rounded text-[9px] font-mono border border-white/10 text-gray-400 bg-black/20"
            >
              {{ vt }}
            </span>
            <span v-if="(r.vuln_types?.length || 0) > 4" class="px-2 py-0.5 rounded text-[9px] font-mono text-gray-600">
              +{{ r.vuln_types.length - 4 }}
            </span>
          </div>

          <!-- Footer -->
          <div class="text-[10px] text-gray-600 font-mono truncate group-hover:text-gray-400 transition-colors">
            {{ r.filename }}
          </div>
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
