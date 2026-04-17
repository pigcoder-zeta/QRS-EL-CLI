<script setup>
import { ref, onMounted, onUnmounted, computed, nextTick } from 'vue'
import {
  Trophy, Play, Loader2, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, Clock, Beaker
} from 'lucide-vue-next'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, RadarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent, RadarComponent } from 'echarts/components'
import {
  fetchBenchmarkPresets, scoreBenchmark, fetchBenchmarkScores,
  startAblation, streamAblation
} from '../api'

use([CanvasRenderer, BarChart, RadarChart, GridComponent, TooltipComponent, LegendComponent, RadarComponent])

const presets = ref([])
const selectedPreset = ref('owasp')
const sarifPath = ref('')
const scoring = ref(false)
const scoreResult = ref(null)
const historicalScores = ref([])
const showHistory = ref(false)

// Ablation
const ablBaseSarif = ref('')
const ablRepoDir = ref('')
const ablLanguage = ref('java')
const ablRunning = ref(false)
const ablTasks = ref([])
const ablComplete = ref(false)
let ablES = null

const doScore = async () => {
  if (!sarifPath.value) return
  scoring.value = true
  try {
    scoreResult.value = await scoreBenchmark(sarifPath.value, selectedPreset.value)
  } catch (e) {
    scoreResult.value = { error: e.message }
  } finally {
    scoring.value = false
  }
}

const radarOption = computed(() => {
  if (!scoreResult.value?.categories?.length) return null
  const cats = scoreResult.value.categories.slice(0, 11)
  return {
    tooltip: { trigger: 'item' },
    radar: {
      indicator: cats.map(c => ({ name: c.label || c.category, max: 1 })),
      shape: 'polygon',
      axisName: { color: '#94a3b8', fontSize: 10 },
      splitArea: { areaStyle: { color: ['rgba(139,92,246,0.05)', 'rgba(139,92,246,0.02)'] } },
      splitLine: { lineStyle: { color: 'rgba(255,255,255,0.05)' } },
      axisLine: { lineStyle: { color: 'rgba(255,255,255,0.08)' } },
    },
    series: [{
      type: 'radar',
      data: [
        {
          value: cats.map(c => c.f1),
          name: 'F1 Score',
          areaStyle: { color: 'rgba(139,92,246,0.2)' },
          lineStyle: { color: '#8B5CF6', width: 2 },
          itemStyle: { color: '#8B5CF6' },
        },
        {
          value: cats.map(c => c.recall),
          name: 'Recall',
          areaStyle: { color: 'rgba(56,189,248,0.1)' },
          lineStyle: { color: '#38BDF8', width: 1 },
          itemStyle: { color: '#38BDF8' },
        }
      ]
    }]
  }
})

const launchAblation = async () => {
  if (!ablBaseSarif.value || !ablRepoDir.value) return
  ablRunning.value = true
  ablComplete.value = false
  ablTasks.value = []
  try {
    const { suite_id } = await startAblation({
      base_sarif: ablBaseSarif.value,
      repo_dir: ablRepoDir.value,
      language: ablLanguage.value,
    })
    ablES = streamAblation(suite_id, {
      task_update: (data) => {
        const idx = data.index
        while (ablTasks.value.length <= idx) ablTasks.value.push({ label: '', status: 'pending', score: null })
        ablTasks.value[idx] = { ...ablTasks.value[idx], ...data }
      },
      complete: () => {
        ablRunning.value = false
        ablComplete.value = true
      },
      error: (data) => {
        ablRunning.value = false
        console.error('Ablation error:', data)
      },
    })
  } catch (e) {
    ablRunning.value = false
    console.error(e)
  }
}

const ablationChartOption = computed(() => {
  const completed = ablTasks.value.filter(t => t.score)
  if (completed.length === 0) return null
  const labels = completed.map(t => t.label || t.name)
  const mkSeries = (name, key, color) => ({
    name, type: 'bar', data: completed.map(t => t.score?.[key] ?? 0),
    itemStyle: { color, borderRadius: [3, 3, 0, 0] }, barMaxWidth: 28,
  })
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { textStyle: { color: '#94a3b8', fontSize: 10 }, bottom: 0 },
    grid: { top: 20, bottom: 40, left: 50, right: 20 },
    xAxis: { type: 'category', data: labels, axisLabel: { color: '#94a3b8', fontSize: 9, rotate: 15 }, axisLine: { lineStyle: { color: 'rgba(255,255,255,0.08)' } } },
    yAxis: { type: 'value', min: 0, max: 1, axisLabel: { color: '#64748b', fontSize: 10 }, splitLine: { lineStyle: { color: 'rgba(255,255,255,0.04)' } } },
    series: [
      mkSeries('F1', 'f1', '#8B5CF6'),
      mkSeries('Precision', 'precision', '#38BDF8'),
      mkSeries('Recall', 'recall', '#10B981'),
      mkSeries('1-FPR', 'fpr', '#F59E0B'),
    ],
  }
})

onMounted(async () => {
  try {
    presets.value = await fetchBenchmarkPresets()
    historicalScores.value = await fetchBenchmarkScores()
  } catch {}
})

onUnmounted(() => { ablES?.close() })
</script>

<template>
  <div class="h-full w-full flex flex-col overflow-hidden">
    <!-- Header -->
    <div class="shrink-0 px-6 pt-5 pb-3 flex items-center gap-3">
      <div class="w-10 h-10 rounded-xl bg-yellow-500/15 flex items-center justify-center border border-yellow-500/30">
        <Trophy class="w-5 h-5 text-yellow-500" />
      </div>
      <div>
        <h2 class="text-lg font-bold text-white tracking-wide font-mono">ARENA</h2>
        <p class="text-[11px] text-gray-500 font-mono">Benchmark 评分 · 消融实验竞技场</p>
      </div>
    </div>

    <div class="flex-1 overflow-y-auto px-6 pb-6 custom-scrollbar space-y-6">
      <!-- Benchmark Section -->
      <div class="glass-panel p-5">
        <div class="text-xs font-mono text-gray-400 tracking-wider mb-4 flex items-center gap-2">
          <Trophy class="w-4 h-4 text-yellow-500" /> BENCHMARK SCORING
        </div>

        <!-- Preset Selection -->
        <div class="flex gap-2 mb-4">
          <button
            v-for="p in presets" :key="p.key"
            @click="selectedPreset = p.key"
            class="px-4 py-2 rounded-lg text-xs font-mono transition-all border"
            :class="selectedPreset === p.key ? 'border-yellow-500/50 bg-yellow-500/10 text-white' : 'border-white/5 text-gray-500 hover:text-gray-300'"
            :title="p.desc"
          >
            {{ p.label }}
          </button>
        </div>

        <!-- SARIF Path + Score -->
        <div class="flex gap-3 mb-4">
          <input
            v-model="sarifPath"
            placeholder="data/results/xxx.sarif (relative to project root)"
            class="flex-1 bg-black/30 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white font-mono placeholder-gray-600 focus:outline-none focus:border-yellow-500/50"
          />
          <button
            @click="doScore"
            :disabled="!sarifPath || scoring"
            class="px-6 py-2.5 rounded-lg font-bold text-xs font-mono border transition-all flex items-center gap-2"
            :class="!sarifPath || scoring ? 'border-gray-700 text-gray-600 cursor-not-allowed' : 'border-yellow-500/50 bg-yellow-500/15 text-yellow-400 hover:bg-yellow-500/25'"
          >
            <Loader2 v-if="scoring" class="w-4 h-4 animate-spin" />
            <Play v-else class="w-4 h-4" />
            SCORE
          </button>
        </div>

        <!-- Score Results -->
        <div v-if="scoreResult && !scoreResult.error" class="space-y-4">
          <div class="grid grid-cols-4 gap-3">
            <div class="bg-black/30 rounded-lg p-3 border border-white/5 text-center">
              <div class="text-2xl font-black font-mono text-argus-purple">{{ scoreResult.overall.f1 }}</div>
              <div class="text-[9px] text-gray-500 font-mono">F1 SCORE</div>
            </div>
            <div class="bg-black/30 rounded-lg p-3 border border-white/5 text-center">
              <div class="text-2xl font-black font-mono text-safe-blue">{{ (scoreResult.overall.precision * 100).toFixed(1) }}%</div>
              <div class="text-[9px] text-gray-500 font-mono">PRECISION</div>
            </div>
            <div class="bg-black/30 rounded-lg p-3 border border-white/5 text-center">
              <div class="text-2xl font-black font-mono text-green-400">{{ (scoreResult.overall.recall * 100).toFixed(1) }}%</div>
              <div class="text-[9px] text-gray-500 font-mono">RECALL</div>
            </div>
            <div class="bg-black/30 rounded-lg p-3 border border-white/5 text-center">
              <div class="text-2xl font-black font-mono text-red-400">{{ (scoreResult.overall.fpr * 100).toFixed(1) }}%</div>
              <div class="text-[9px] text-gray-500 font-mono">FPR</div>
            </div>
          </div>

          <!-- Radar Chart -->
          <div v-if="radarOption" class="h-80">
            <v-chart :option="radarOption" autoresize />
          </div>

          <!-- Per-category table -->
          <div class="overflow-x-auto">
            <table class="w-full text-[11px] font-mono">
              <thead>
                <tr class="text-gray-500 border-b border-white/5">
                  <th class="text-left py-2 px-2">Category</th>
                  <th class="text-center py-2 px-2">TP</th>
                  <th class="text-center py-2 px-2">FP</th>
                  <th class="text-center py-2 px-2">Precision</th>
                  <th class="text-center py-2 px-2">Recall</th>
                  <th class="text-center py-2 px-2">F1</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="c in scoreResult.categories" :key="c.category" class="border-b border-white/5 hover:bg-white/5">
                  <td class="py-2 px-2 text-white">{{ c.label || c.category }}</td>
                  <td class="py-2 px-2 text-center text-green-400">{{ c.tp }}</td>
                  <td class="py-2 px-2 text-center text-red-400">{{ c.fp }}</td>
                  <td class="py-2 px-2 text-center">{{ (c.precision * 100).toFixed(1) }}%</td>
                  <td class="py-2 px-2 text-center">{{ (c.recall * 100).toFixed(1) }}%</td>
                  <td class="py-2 px-2 text-center text-argus-purple font-bold">{{ c.f1.toFixed(3) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div v-if="scoreResult?.error" class="text-red-400 text-xs font-mono p-3 bg-red-500/5 rounded-lg border border-red-500/20">
          {{ scoreResult.error }}
        </div>

        <!-- Historical -->
        <div v-if="historicalScores.length" class="mt-4">
          <button @click="showHistory = !showHistory" class="flex items-center gap-2 text-[10px] font-mono text-gray-500 hover:text-gray-300 transition-colors">
            <ChevronDown v-if="!showHistory" class="w-3 h-3" />
            <ChevronUp v-else class="w-3 h-3" />
            {{ historicalScores.length }} HISTORICAL SCORES
          </button>
          <div v-if="showHistory" class="mt-2 space-y-1">
            <div v-for="s in historicalScores" :key="s._filename"
                 class="flex items-center gap-3 px-3 py-2 rounded bg-black/20 border border-white/5 text-[10px] font-mono">
              <span class="text-gray-500 w-32 truncate">{{ s._filename }}</span>
              <span class="text-argus-purple font-bold">F1: {{ s.overall?.f1?.toFixed(3) }}</span>
              <span class="text-gray-400">P: {{ ((s.overall?.precision || 0) * 100).toFixed(1) }}%</span>
              <span class="text-gray-400">FPR: {{ ((s.overall?.fpr || 0) * 100).toFixed(1) }}%</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Ablation Section -->
      <div class="glass-panel p-5">
        <div class="text-xs font-mono text-gray-400 tracking-wider mb-4 flex items-center gap-2">
          <Beaker class="w-4 h-4 text-argus-purple" /> ABLATION ARENA
        </div>

        <div class="grid grid-cols-3 gap-3 mb-4">
          <label class="flex flex-col gap-1">
            <span class="text-[10px] text-gray-500 font-mono">Base SARIF（相对路径）</span>
            <input v-model="ablBaseSarif" placeholder="data/results/xxx.sarif"
                   class="bg-black/30 border border-white/10 rounded px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-argus-purple/50" />
          </label>
          <label class="flex flex-col gap-1">
            <span class="text-[10px] text-gray-500 font-mono">Repo Directory（相对路径）</span>
            <input v-model="ablRepoDir" placeholder="data/workspaces/xxx"
                   class="bg-black/30 border border-white/10 rounded px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-argus-purple/50" />
          </label>
          <label class="flex flex-col gap-1">
            <span class="text-[10px] text-gray-500 font-mono">Language</span>
            <select v-model="ablLanguage" class="bg-black/30 border border-white/10 rounded px-3 py-2 text-xs text-gray-300 font-mono focus:outline-none">
              <option v-for="l in ['java','python','javascript','go','csharp','cpp']" :key="l" :value="l">{{ l }}</option>
            </select>
          </label>
        </div>

        <button
          @click="launchAblation"
          :disabled="ablRunning || !ablBaseSarif || !ablRepoDir"
          class="px-6 py-3 rounded-lg font-bold text-sm font-mono border-2 transition-all flex items-center gap-2 mb-4"
          :class="ablRunning || !ablBaseSarif || !ablRepoDir
            ? 'border-gray-700 text-gray-600 cursor-not-allowed'
            : 'border-argus-purple bg-argus-purple/15 text-white hover:bg-argus-purple/30'"
        >
          <Loader2 v-if="ablRunning" class="w-4 h-4 animate-spin" />
          <Beaker v-else class="w-4 h-4" />
          {{ ablRunning ? 'RUNNING...' : 'START ABLATION' }}
        </button>

        <!-- Variant Cards -->
        <div v-if="ablTasks.length" class="grid grid-cols-5 gap-3 mb-4">
          <div v-for="(t, idx) in ablTasks" :key="idx"
               class="rounded-lg border p-3 text-center transition-all"
               :class="{
                 'border-white/5 bg-black/20': t.status === 'pending',
                 'border-argus-purple/40 bg-argus-purple/10 animate-pulse': t.status === 'running',
                 'border-green-500/30 bg-green-500/5': t.status === 'completed',
                 'border-red-500/30 bg-red-500/5': t.status === 'error',
               }">
            <div class="text-[9px] font-mono text-gray-400 mb-1 truncate">{{ t.label }}</div>
            <div v-if="t.status === 'completed' && t.score" class="text-lg font-black font-mono text-argus-purple">
              {{ t.score.f1?.toFixed(3) }}
            </div>
            <div v-else-if="t.status === 'running'" class="py-1">
              <Loader2 class="w-5 h-5 text-argus-purple animate-spin mx-auto" />
            </div>
            <div v-else-if="t.status === 'error'" class="py-1">
              <XCircle class="w-5 h-5 text-red-500 mx-auto" />
            </div>
            <div v-else class="py-1">
              <Clock class="w-5 h-5 text-gray-600 mx-auto" />
            </div>
            <div v-if="t.score" class="text-[8px] font-mono text-gray-500 mt-1">
              FPR: {{ ((t.score.fpr || 0) * 100).toFixed(1) }}%
            </div>
          </div>
        </div>

        <!-- Ablation Chart -->
        <div v-if="ablationChartOption" class="h-72">
          <v-chart :option="ablationChartOption" autoresize />
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
