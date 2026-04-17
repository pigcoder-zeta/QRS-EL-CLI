<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { ScatterChart, LinesChart, EffectScatterChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import 'echarts-gl'

const props = defineProps({
  isTracing: { type: Boolean, default: false },
  externalSignals: { type: Array, default: () => [] },
  scanning: { type: Boolean, default: false },
})

use([CanvasRenderer, ScatterChart, LinesChart, EffectScatterChart, GridComponent, TooltipComponent])

const agentDefs = [
  { id: 'T', name: 'Agent-T', x: 25, y: 70 },
  { id: 'Q', name: 'Agent-Q', x: 75, y: 70 },
  { id: 'S', name: 'Agent-S', x: 85, y: 30 },
  { id: 'R', name: 'Agent-R', x: 95, y: 50 },
  { id: 'E', name: 'Agent-E', x: 15, y: 30 },
  { id: 'P', name: 'Agent-P', x: 50, y: 50, isCenter: true },
]

const agentMap = Object.fromEntries(agentDefs.map(a => [a.id, a]))

const liveParticles = ref([])

watch(() => props.externalSignals, (sigs) => {
  if (!sigs || sigs.length === 0) return
  for (const sig of sigs) {
    const from = agentMap[sig.from]
    const to = agentMap[sig.to]
    if (!from || !to) continue
    liveParticles.value.push({
      id: Date.now() + Math.random(),
      source: from, target: to,
      type: sig.type || 'neural',
      progress: 0,
      label: sig.label || '',
    })
  }
  if (liveParticles.value.length > 20) {
    liveParticles.value = liveParticles.value.slice(-20)
  }
}, { deep: true })

const holographicOption = computed(() => {
  const p = agentMap['P']
  const others = agentDefs.filter(a => !a.isCenter)
  const baseLinesData = others.map(a => ({ coords: [[p.x, p.y], [a.x, a.y]] }))

  const outEffect = props.scanning
  const outgoing = others.map(a => ({ coords: [[p.x, p.y], [a.x, a.y]] }))
  const incoming = others.map(a => ({ coords: [[a.x, a.y], [p.x, p.y]] }))

  return {
    grid: { top: 0, bottom: 0, left: 0, right: 0 },
    xAxis: { type: 'value', min: 0, max: 100, show: false },
    yAxis: { type: 'value', min: 0, max: 100, show: false, inverse: true },
    series: [
      {
        type: 'scatter', coordinateSystem: 'cartesian2d', symbol: 'circle', symbolSize: 300,
        itemStyle: { color: 'transparent', borderColor: 'rgba(168,85,247,0.15)', borderWidth: 2, borderType: 'dashed' },
        data: [[50, 50]], zlevel: 0,
      },
      {
        type: 'lines', coordinateSystem: 'cartesian2d', data: baseLinesData,
        lineStyle: { color: '#a855f7', width: 1, opacity: props.scanning ? 0.25 : 0.1, curveness: 0.15 }, zlevel: 1,
      },
      ...(outEffect ? [
        {
          type: 'lines', coordinateSystem: 'cartesian2d', data: outgoing,
          lineStyle: { width: 0, curveness: 0.15 },
          effect: { show: true, period: 3, trailLength: 0.4, symbol: 'circle', symbolSize: 5, color: '#c084fc' },
          zlevel: 2,
        },
        {
          type: 'lines', coordinateSystem: 'cartesian2d', data: incoming,
          lineStyle: { width: 0, curveness: 0.15 },
          effect: { show: true, period: 4, trailLength: 0.4, symbol: 'circle', symbolSize: 5, color: '#38bdf8' },
          zlevel: 2,
        },
      ] : []),
      {
        type: 'effectScatter', coordinateSystem: 'cartesian2d', symbol: 'circle',
        symbolSize: (val, params) => params.data.isCenter ? 80 : 40,
        itemStyle: {
          color: (params) => ({
            type: 'radial', x: 0.5, y: 0.5, r: 0.5,
            colorStops: params.data.isCenter
              ? [{ offset: 0, color: '#f3e8ff' }, { offset: 1, color: '#a855f7' }]
              : [{ offset: 0, color: '#e0f2fe' }, { offset: 1, color: '#0ea5e9' }],
          }),
          shadowBlur: (params) => params.data.isCenter ? 50 : 30,
          shadowColor: (params) => params.data.isCenter ? '#a855f7' : '#0ea5e9',
        },
        rippleEffect: { brushType: 'stroke', scale: props.scanning ? 3 : 2, period: props.scanning ? 3 : 5 },
        label: {
          show: true, position: 'bottom', distance: 20, color: '#e2e8f0', fontSize: 13,
          fontWeight: 'bold', textShadowBlur: 10, textShadowColor: '#000', formatter: '{b}',
          backgroundColor: 'transparent', borderWidth: 0, padding: 0,
        },
        data: agentDefs.map(a => ({ name: a.name, value: [a.x, a.y], isCenter: !!a.isCenter })),
        zlevel: 3,
      },
    ],
  }
})

const connections = computed(() => {
  const p = agentMap['P']
  return agentDefs.filter(a => !a.isCenter).map(a => ({ id: `P-${a.id}`, x1: p.x, y1: p.y, x2: a.x, y2: a.y }))
})

let animFrame
onMounted(() => {
  const animate = () => {
    liveParticles.value.forEach(s => s.progress += 0.018)
    liveParticles.value = liveParticles.value.filter(s => s.progress <= 1)
    animFrame = requestAnimationFrame(animate)
  }
  animFrame = requestAnimationFrame(animate)
})
onUnmounted(() => { cancelAnimationFrame(animFrame) })

const getSignalColor = (type) => type === 'neural' ? '#8B5CF6' : '#38BDF8'
</script>

<template>
  <div class="w-full h-full relative perspective-1500 flex items-center justify-center overflow-hidden">

    <div class="w-[800px] h-[800px] absolute transform-3d tilt-chart" style="top: 50%; left: 50%; margin-left: -400px; margin-top: -350px;">

      <svg class="absolute inset-0 w-full h-full pointer-events-none opacity-20" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="38" fill="none" :stroke="scanning ? '#8B5CF6' : '#0EA5E9'" stroke-width="0.2" stroke-dasharray="1 2" class="transition-colors duration-1000" />
        <circle cx="50" cy="50" r="23" fill="none" :stroke="scanning ? '#c084fc' : '#8B5CF6'" stroke-width="0.1" class="transition-colors duration-1000" />
        <circle cx="50" cy="50" r="8" fill="none" :stroke="scanning ? '#8B5CF6' : '#0EA5E9'" stroke-width="0.3" stroke-dasharray="2 4" class="transition-colors duration-1000" :class="scanning ? 'animate-spin-slow' : ''" style="transform-origin: 50% 50%" />
      </svg>

      <svg class="absolute inset-0 w-full h-full pointer-events-none overflow-visible" viewBox="0 0 100 100">
        <defs>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>
        <line v-for="conn in connections" :key="conn.id"
              :x1="conn.x1" :y1="conn.y1" :x2="conn.x2" :y2="conn.y2"
              :stroke="scanning ? 'rgba(139,92,246,0.25)' : 'rgba(139,92,246,0.1)'"
              :stroke-width="scanning ? 0.6 : 0.3" class="transition-all duration-1000" />

        <!-- Real live particles driven by SSE -->
        <circle v-for="p in liveParticles" :key="p.id"
                :cx="p.source.x + (p.target.x - p.source.x) * p.progress"
                :cy="p.source.y + (p.target.y - p.source.y) * p.progress"
                :r="1.5" :fill="getSignalColor(p.type)" filter="url(#glow)" />
      </svg>

      <div class="absolute inset-0 w-full h-full pointer-events-none z-20">
        <v-chart :option="holographicOption" autoresize />
      </div>

      <!-- Live signal labels (briefly flash near the midpoint) -->
      <div v-for="p in liveParticles.filter(x => x.label && x.progress > 0.3 && x.progress < 0.7)" :key="'lbl-'+p.id"
           class="absolute -translate-x-1/2 -translate-y-1/2 pointer-events-none counter-tilt z-30"
           :style="{ left: `${p.source.x + (p.target.x - p.source.x) * p.progress}%`, top: `${p.source.y + (p.target.y - p.source.y) * p.progress}%`, opacity: 0.9 }">
        <div class="px-2 py-1 rounded bg-[#020617]/90 border text-[9px] font-mono whitespace-nowrap shadow-lg"
             :style="{ borderColor: getSignalColor(p.type), color: '#e2e8f0', boxShadow: `0 0 8px ${getSignalColor(p.type)}40` }">
          {{ p.label }}
        </div>
      </div>
    </div>

    <slot name="overlay" />

    <!-- Legend -->
    <div class="absolute bottom-4 left-4 glass-panel p-3 border-white/5 flex gap-4 text-[10px] font-mono text-gray-400">
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-argus-purple shadow-[0_0_5px_#8B5CF6]"></span>
        Neural (LLM)
      </div>
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-safe-blue shadow-[0_0_5px_#38BDF8]"></span>
        Symbolic (CodeQL)
      </div>
      <div v-if="scanning" class="flex items-center gap-2 text-green-400">
        <span class="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
        LIVE
      </div>
    </div>
  </div>
</template>

<style scoped>
.perspective-1500 { perspective: 1500px; }
.transform-3d { transform-style: preserve-3d; }
.tilt-chart {
  transform: perspective(1000px) rotateX(60deg) scale(0.85);
  animation: floatHologram 6s ease-in-out infinite;
}
.counter-tilt {
  transform: rotateZ(30deg) rotateX(-65deg);
  transform-origin: center bottom;
}
@keyframes floatHologram {
  0%, 100% { transform: perspective(1000px) rotateX(60deg) scale(0.85) translateZ(0px); }
  50% { transform: perspective(1000px) rotateX(60deg) scale(0.85) translateZ(20px); }
}
</style>
