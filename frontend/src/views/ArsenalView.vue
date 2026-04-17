<script setup>
import { ref, onMounted, computed } from 'vue'
import {
  Swords, Code, Database, Search, Download, Upload, Trash2, ShieldCheck, ShieldAlert,
  ShieldX, ShieldQuestion, ChevronRight, X, CheckCircle2, AlertTriangle, Filter
} from 'lucide-vue-next'
import {
  fetchTemplates, fetchTemplateStats, testTemplateMatch,
  fetchMemory, searchMemory, fetchMemoryCode, exportMemory,
  importMemory, clearMemory, verifyMemory, quarantineMemory, checkMemoryIntegrity
} from '../api'
import Prism from 'prismjs'
import 'prismjs/components/prism-sql'
import 'prismjs/themes/prism-tomorrow.css'

const activeTab = ref('templates')

// --- Templates ---
const templates = ref([])
const templateStats = ref({ total: 0, by_language: {} })
const templateFilter = ref('')
const expandedTemplate = ref(null)
const matchLang = ref('java')
const matchKeyword = ref('')
const matchResult = ref(null)

const filteredTemplates = computed(() => {
  if (!templateFilter.value) return templates.value
  return templates.value.filter(t => t.language === templateFilter.value)
})

const templateLangs = computed(() => Object.keys(templateStats.value.by_language || {}))

const doMatchTest = async () => {
  if (!matchKeyword.value) return
  try {
    matchResult.value = await testTemplateMatch(matchLang.value, matchKeyword.value)
  } catch { matchResult.value = { matched: false, reason: 'error' } }
}

const showTemplateCode = (t) => {
  expandedTemplate.value = expandedTemplate.value?.key === t.key ? null : t
}

// --- Memory ---
const memory = ref({ total: 0, backend: '', records: [], trust_stats: {} })
const memorySearchQuery = ref('')
const memorySearchLang = ref('java')
const memorySearchResults = ref([])
const codeModal = ref(null)
const integrityResult = ref(null)
const memoryFilter = ref('')

const filteredRecords = computed(() => {
  if (!memoryFilter.value) return memory.value.records
  return memory.value.records.filter(r => r.trust_level === memoryFilter.value)
})

const trustColors = {
  trusted: 'text-green-400 bg-green-500/10 border-green-500/30',
  verified: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  unverified: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  quarantined: 'text-red-400 bg-red-500/10 border-red-500/30',
}

const trustIcons = { trusted: ShieldCheck, verified: CheckCircle2, unverified: ShieldQuestion, quarantined: ShieldX }

const doMemorySearch = async () => {
  if (!memorySearchQuery.value) return
  try {
    const res = await searchMemory(memorySearchQuery.value, memorySearchLang.value)
    memorySearchResults.value = res.results || []
  } catch {}
}

const showCode = async (ruleId) => {
  try {
    const res = await fetchMemoryCode(ruleId)
    codeModal.value = { ruleId, code: res.ql_code }
  } catch { codeModal.value = { ruleId, code: '// Failed to load' } }
}

const doVerify = async (ruleId) => {
  try { await verifyMemory(ruleId); await loadMemory() } catch {}
}
const doQuarantine = async (ruleId) => {
  try { await quarantineMemory(ruleId); await loadMemory() } catch {}
}
const doIntegrity = async () => {
  try { integrityResult.value = await checkMemoryIntegrity() } catch {}
}
const doExport = () => { window.open(exportMemory(), '_blank') }
const doImport = async () => {
  const input = document.createElement('input')
  input.type = 'file'
  input.accept = '.zip'
  input.onchange = async (e) => {
    const file = e.target.files[0]
    if (file) {
      try { await importMemory(file); await loadMemory() } catch {}
    }
  }
  input.click()
}
const doClear = async () => {
  if (!confirm('确定要清空整个知识库？此操作不可撤销。')) return
  try { await clearMemory(); await loadMemory() } catch {}
}

const loadMemory = async () => {
  try { memory.value = await fetchMemory() } catch {}
}

onMounted(async () => {
  try {
    const [tplRes, statsRes] = await Promise.all([fetchTemplates(), fetchTemplateStats()])
    templates.value = tplRes.templates || []
    templateStats.value = statsRes
  } catch {}
  await loadMemory()
})
</script>

<template>
  <div class="h-full w-full flex flex-col overflow-hidden">
    <!-- Header -->
    <div class="shrink-0 px-6 pt-5 pb-3 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-neon-purple/15 flex items-center justify-center border border-neon-purple/30">
          <Swords class="w-5 h-5 text-neon-purple" />
        </div>
        <div>
          <h2 class="text-lg font-bold text-white tracking-wide font-mono">ARSENAL</h2>
          <p class="text-[11px] text-gray-500 font-mono">黄金模板库 · 规则知识库</p>
        </div>
      </div>
      <!-- Tabs -->
      <div class="flex gap-1 bg-black/30 p-1 rounded-lg border border-white/5">
        <button
          @click="activeTab = 'templates'"
          class="px-4 py-2 rounded-md text-xs font-mono font-bold transition-all flex items-center gap-2"
          :class="activeTab === 'templates' ? 'bg-argus-purple/20 text-white' : 'text-gray-500 hover:text-gray-300'"
        >
          <Code class="w-3.5 h-3.5" /> TEMPLATES
        </button>
        <button
          @click="activeTab = 'memory'"
          class="px-4 py-2 rounded-md text-xs font-mono font-bold transition-all flex items-center gap-2"
          :class="activeTab === 'memory' ? 'bg-safe-blue/20 text-white' : 'text-gray-500 hover:text-gray-300'"
        >
          <Database class="w-3.5 h-3.5" /> KNOWLEDGE BASE
        </button>
      </div>
    </div>

    <!-- Templates Tab -->
    <div v-if="activeTab === 'templates'" class="flex-1 overflow-y-auto px-6 pb-6 custom-scrollbar">
      <!-- Stats + Filter + Match Test -->
      <div class="flex gap-4 mb-4">
        <div class="glass-panel p-4 flex-1">
          <div class="text-[10px] text-gray-500 font-mono mb-1">TOTAL TEMPLATES</div>
          <div class="text-2xl font-black font-mono text-argus-purple">{{ templateStats.total }}</div>
          <div class="flex gap-2 mt-2 flex-wrap">
            <span v-for="(count, lang) in templateStats.by_language" :key="lang"
                  class="text-[9px] font-mono px-2 py-0.5 rounded bg-black/30 border border-white/5 text-gray-400">
              {{ lang }}: {{ count }}
            </span>
          </div>
        </div>
        <div class="glass-panel p-4 w-80">
          <div class="text-[10px] text-gray-500 font-mono mb-2">MATCH TEST</div>
          <div class="flex gap-2">
            <select v-model="matchLang" class="bg-black/30 border border-white/10 rounded px-2 py-1.5 text-xs text-gray-300 font-mono focus:outline-none w-24">
              <option v-for="l in templateLangs" :key="l" :value="l">{{ l }}</option>
            </select>
            <input v-model="matchKeyword" placeholder="keyword..." @keydown.enter="doMatchTest"
                   class="flex-1 bg-black/30 border border-white/10 rounded px-3 py-1.5 text-xs text-white font-mono placeholder-gray-600 focus:outline-none focus:border-argus-purple/50" />
            <button @click="doMatchTest" class="px-3 py-1.5 rounded bg-argus-purple/20 border border-argus-purple/30 text-argus-purple text-xs font-bold hover:bg-argus-purple/30 transition-all">
              TEST
            </button>
          </div>
          <div v-if="matchResult" class="mt-2 text-[10px] font-mono" :class="matchResult.matched ? 'text-green-400' : 'text-gray-500'">
            {{ matchResult.matched ? `✓ Matched: ${matchResult.template?.key}` : `✗ ${matchResult.reason}` }}
          </div>
        </div>
      </div>

      <!-- Language filter -->
      <div class="flex gap-2 mb-4">
        <button @click="templateFilter = ''" class="px-3 py-1 rounded-md text-[10px] font-mono transition-all border"
                :class="!templateFilter ? 'border-argus-purple/40 bg-argus-purple/10 text-white' : 'border-white/5 text-gray-500 hover:text-gray-300'">ALL</button>
        <button v-for="l in templateLangs" :key="l" @click="templateFilter = l"
                class="px-3 py-1 rounded-md text-[10px] font-mono transition-all border"
                :class="templateFilter === l ? 'border-argus-purple/40 bg-argus-purple/10 text-white' : 'border-white/5 text-gray-500 hover:text-gray-300'">
          {{ l.toUpperCase() }}
        </button>
      </div>

      <!-- Template Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        <div v-for="t in filteredTemplates" :key="t.key"
             @click="showTemplateCode(t)"
             class="glass-panel p-4 cursor-pointer hover:border-argus-purple/30 transition-all group">
          <div class="flex items-center gap-2 mb-2">
            <span class="px-2 py-0.5 rounded text-[9px] font-mono font-bold border border-safe-blue/30 bg-safe-blue/10 text-safe-blue">{{ t.language }}</span>
            <span class="text-xs font-mono text-white font-bold">{{ t.vuln_type }}</span>
          </div>
          <div class="text-[10px] text-gray-500 line-clamp-2">{{ t.description }}</div>
          <div class="text-[9px] text-gray-600 mt-2 font-mono flex items-center gap-1 group-hover:text-argus-purple transition-colors">
            <ChevronRight class="w-3 h-3" /> VIEW QL CODE
          </div>
        </div>
      </div>

      <!-- Code slideout -->
      <transition name="fade">
        <div v-if="expandedTemplate" class="fixed inset-0 z-50 flex justify-end" @click.self="expandedTemplate = null">
          <div class="w-[600px] h-full bg-cyber-dark border-l border-white/10 shadow-2xl flex flex-col">
            <div class="px-5 py-4 border-b border-white/5 flex items-center justify-between shrink-0">
              <div>
                <span class="text-xs font-mono text-safe-blue">{{ expandedTemplate.language }}</span>
                <span class="text-sm font-mono text-white font-bold ml-2">{{ expandedTemplate.vuln_type }}</span>
              </div>
              <button @click="expandedTemplate = null" class="p-1 rounded hover:bg-white/10 text-gray-500"><X class="w-4 h-4" /></button>
            </div>
            <div class="flex-1 overflow-auto p-4 bg-[#1d1f21]">
              <pre class="!m-0 !p-0 !bg-transparent text-[12px] font-mono"><code class="language-sql">{{ expandedTemplate.ql_code }}</code></pre>
            </div>
          </div>
        </div>
      </transition>
    </div>

    <!-- Memory Tab -->
    <div v-if="activeTab === 'memory'" class="flex-1 overflow-y-auto px-6 pb-6 custom-scrollbar">
      <!-- Stats -->
      <div class="flex gap-4 mb-4">
        <div class="glass-panel p-4 flex-1">
          <div class="flex items-center justify-between mb-2">
            <div class="text-[10px] text-gray-500 font-mono">KNOWLEDGE BASE</div>
            <span class="text-[9px] font-mono text-gray-600">{{ memory.backend }}</span>
          </div>
          <div class="text-2xl font-black font-mono text-safe-blue">{{ memory.total }}</div>
          <div class="flex gap-3 mt-2">
            <div v-for="(count, level) in memory.trust_stats" :key="level" class="flex items-center gap-1">
              <component :is="trustIcons[level] || ShieldQuestion" class="w-3 h-3" :class="trustColors[level]?.split(' ')[0]" />
              <span class="text-[9px] font-mono text-gray-400">{{ level }}: {{ count }}</span>
            </div>
          </div>
        </div>

        <!-- Search -->
        <div class="glass-panel p-4 w-96">
          <div class="text-[10px] text-gray-500 font-mono mb-2">SEMANTIC SEARCH</div>
          <div class="flex gap-2">
            <select v-model="memorySearchLang" class="bg-black/30 border border-white/10 rounded px-2 py-1.5 text-xs text-gray-300 font-mono focus:outline-none w-24">
              <option v-for="l in ['java','python','javascript','go','csharp','cpp','solidity']" :key="l" :value="l">{{ l }}</option>
            </select>
            <input v-model="memorySearchQuery" placeholder="Search query..." @keydown.enter="doMemorySearch"
                   class="flex-1 bg-black/30 border border-white/10 rounded px-3 py-1.5 text-xs text-white font-mono placeholder-gray-600 focus:outline-none focus:border-safe-blue/50" />
            <button @click="doMemorySearch" class="px-3 py-1.5 rounded bg-safe-blue/20 border border-safe-blue/30 text-safe-blue text-xs font-bold hover:bg-safe-blue/30 transition-all">
              <Search class="w-3.5 h-3.5" />
            </button>
          </div>
          <div v-if="memorySearchResults.length" class="mt-2 space-y-1 max-h-32 overflow-y-auto">
            <div v-for="r in memorySearchResults" :key="r.rule_id" class="text-[10px] font-mono flex items-center gap-2 px-2 py-1 rounded bg-black/20">
              <span class="text-safe-blue">{{ r.score }}</span>
              <span class="text-gray-400 truncate flex-1">{{ r.vuln_type }} · {{ r.language }}</span>
              <button @click="showCode(r.rule_id)" class="text-gray-500 hover:text-white"><Code class="w-3 h-3" /></button>
            </div>
          </div>
        </div>
      </div>

      <!-- Toolbar -->
      <div class="flex gap-2 mb-4">
        <button @click="memoryFilter = ''" class="px-3 py-1 rounded-md text-[10px] font-mono border transition-all"
                :class="!memoryFilter ? 'border-safe-blue/40 bg-safe-blue/10 text-white' : 'border-white/5 text-gray-500 hover:text-gray-300'">ALL</button>
        <button v-for="level in ['trusted','verified','unverified','quarantined']" :key="level"
                @click="memoryFilter = level"
                class="px-3 py-1 rounded-md text-[10px] font-mono border transition-all"
                :class="memoryFilter === level ? trustColors[level] + ' border-current' : 'border-white/5 text-gray-500 hover:text-gray-300'">
          {{ level.toUpperCase() }}
        </button>
        <div class="flex-1"></div>
        <button @click="doExport" class="px-3 py-1.5 rounded text-[10px] font-mono text-gray-400 hover:text-white border border-white/10 hover:border-white/20 flex items-center gap-1 transition-all">
          <Download class="w-3 h-3" /> Export
        </button>
        <button @click="doImport" class="px-3 py-1.5 rounded text-[10px] font-mono text-gray-400 hover:text-white border border-white/10 hover:border-white/20 flex items-center gap-1 transition-all">
          <Upload class="w-3 h-3" /> Import
        </button>
        <button @click="doIntegrity" class="px-3 py-1.5 rounded text-[10px] font-mono text-gray-400 hover:text-white border border-white/10 hover:border-white/20 flex items-center gap-1 transition-all">
          <ShieldCheck class="w-3 h-3" /> Verify
        </button>
        <button @click="doClear" class="px-3 py-1.5 rounded text-[10px] font-mono text-red-500/60 hover:text-red-400 border border-red-500/20 hover:border-red-500/40 flex items-center gap-1 transition-all">
          <Trash2 class="w-3 h-3" /> Clear
        </button>
      </div>

      <!-- Integrity result -->
      <div v-if="integrityResult" class="glass-panel p-3 mb-4 text-[11px] font-mono">
        <span class="text-gray-500">Integrity check:</span>
        <span class="ml-2 text-green-400">{{ integrityResult.valid || 0 }} valid</span>
        <span class="ml-2 text-red-400">{{ integrityResult.tampered || 0 }} tampered</span>
        <span class="ml-2 text-gray-500">{{ integrityResult.missing || 0 }} missing</span>
      </div>

      <!-- Records -->
      <div class="space-y-2">
        <div v-for="rec in filteredRecords" :key="rec.rule_id"
             class="glass-panel p-3 flex items-center gap-3 text-[11px] font-mono">
          <component :is="trustIcons[rec.trust_level] || ShieldQuestion" class="w-4 h-4 shrink-0" :class="trustColors[rec.trust_level]?.split(' ')[0]" />
          <span class="px-2 py-0.5 rounded border text-[9px] font-bold" :class="trustColors[rec.trust_level]">{{ rec.trust_level }}</span>
          <span class="text-gray-400 w-16">{{ rec.language }}</span>
          <span class="text-white flex-1 truncate">{{ rec.vuln_type }}</span>
          <span class="text-gray-600 w-32 text-right truncate">{{ rec.created_at?.slice(0, 16) }}</span>
          <div class="flex gap-1 shrink-0">
            <button @click="showCode(rec.rule_id)" class="px-2 py-1 rounded bg-black/20 border border-white/5 text-gray-500 hover:text-white transition-all" title="View Code">
              <Code class="w-3 h-3" />
            </button>
            <button @click="doVerify(rec.rule_id)" class="px-2 py-1 rounded bg-black/20 border border-white/5 text-gray-500 hover:text-green-400 transition-all" title="Verify">
              <CheckCircle2 class="w-3 h-3" />
            </button>
            <button @click="doQuarantine(rec.rule_id)" class="px-2 py-1 rounded bg-black/20 border border-white/5 text-gray-500 hover:text-red-400 transition-all" title="Quarantine">
              <ShieldX class="w-3 h-3" />
            </button>
          </div>
        </div>
        <div v-if="filteredRecords.length === 0" class="text-center text-gray-600 py-8 font-mono text-xs">NO RECORDS</div>
      </div>

      <!-- Code Modal -->
      <transition name="fade">
        <div v-if="codeModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" @click.self="codeModal = null">
          <div class="w-[700px] max-h-[80vh] bg-cyber-dark border border-white/10 rounded-xl shadow-2xl flex flex-col overflow-hidden">
            <div class="px-5 py-3 border-b border-white/5 flex items-center justify-between shrink-0">
              <span class="text-sm font-mono text-white">{{ codeModal.ruleId }}</span>
              <button @click="codeModal = null" class="p-1 rounded hover:bg-white/10 text-gray-500"><X class="w-4 h-4" /></button>
            </div>
            <div class="flex-1 overflow-auto p-4 bg-[#1d1f21]">
              <pre class="!m-0 !p-0 !bg-transparent text-[12px] font-mono"><code class="language-sql">{{ codeModal.code }}</code></pre>
            </div>
          </div>
        </div>
      </transition>
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar { width: 4px; }
.custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.2); border-radius: 2px; }
</style>
