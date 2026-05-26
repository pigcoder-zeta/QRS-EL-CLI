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

const agentDescriptions = {
  'Agent-P': {
    title: 'Agent-P · Planner',
    subtitle: '元决策层',
    desc: '自动侦察目标仓库的语言、框架、依赖与入口点，从全域安全检测矩阵中智能规划扫描策略。每轮扫描后评估结果质量，决定继续、重扫或终止，实现零配置自动化。',
    tags: ['侦察', '规划', '质量评估'],
    color: '#a855f7',
  },
  'Agent-T': {
    title: 'Agent-T · Triage',
    subtitle: '智能分诊器',
    desc: '采用"规则引擎优先 + LLM 降级"混合策略，自动识别 7 类代码库（Web 应用 / 内核模块 / 移动端 / 智能合约等），输出攻击面画像，驱动下游 Agent 的策略选择与提示预设。',
    tags: ['7 类识别', '攻击面', '零 LLM 成本'],
    color: '#0ea5e9',
  },
  'Agent-Q': {
    title: 'Agent-Q · Query',
    subtitle: '规则合成器',
    desc: '遵循"黄金模板引导优先、约束驱动定向生成、编译反馈闭环自修复"三阶策略。内置 49 个预验证模板覆盖 15 类漏洞，LLM 直接生成编译成功率不足 30%，经自修复闭环提升至生产标准。',
    tags: ['49 模板', '自修复', 'RAG 增强'],
    color: '#0ea5e9',
  },
  'Agent-R': {
    title: 'Agent-R · Review',
    subtitle: '语义审查器',
    desc: '对每条 SARIF 告警进行深度语义审查。内置符号级代码导航引擎（CodeBrowser），支持符号定义查询、引用追踪、数据流展开，为 LLM 提供最大信息密度上下文。将误报率从 34.9% 降至 10.0%。',
    tags: ['CodeBrowser', '误报率 -72.5%', 'CoT 推理'],
    color: '#0ea5e9',
  },
  'Agent-S': {
    title: 'Agent-S · Synthesize',
    subtitle: 'PoC 生成器',
    desc: '内置 18 类漏洞专属 Payload 策略模板，覆盖 SpEL / OGNL / SQL / 命令注入 / 路径穿越 / SSRF 等主流 Web 漏洞利用场景，结合源码上下文 LLM 定制化生成可直接使用的 Exploit PoC。',
    tags: ['18 类策略', 'Payload 定制', 'Exploit'],
    color: '#0ea5e9',
  },
  'Agent-E': {
    title: 'Agent-E · Execute',
    subtitle: '沙箱验证器',
    desc: '在隔离 Docker 容器中执行 PoC，实时监测网络回显、文件变更及响应状态，捕获运行时证据。只有经沙箱复现确认的漏洞才被标记为 CONFIRMED，实现从静态告警到运行时实证的闭环。',
    tags: ['Docker 沙箱', '运行时实证', 'CONFIRMED'],
    color: '#0ea5e9',
  },
}

const emit = defineEmits(['agent-hover'])
const hoveredAgent = ref(null)
const chartRef = ref(null)

const agentMap = Object.fromEntries(agentDefs.map(a => [a.id, a]))

const liveParticles = ref([])
const INTERACTIVE_SIGNAL_MS = 520
const interactiveSignalTs = {}
const HEARTBEAT_EDGES = [['P', 'T'], ['T', 'Q'], ['Q', 'R'], ['R', 'S'], ['S', 'E'], ['E', 'P']]
let heartbeatTimer = null
let heartbeatEdgeIdx = 0

function pushSignalParticle (sig) {
  const from = agentMap[sig.from]
  const to = agentMap[sig.to]
  if (!from || !to) return
  liveParticles.value.push({
    id: Date.now() + Math.random(),
    source: from,
    target: to,
    type: sig.type || 'neural',
    size: sig.size || 'small',
    progress: 0,
    label: sig.label || '',
  })
  if (liveParticles.value.length > 28) {
    liveParticles.value = liveParticles.value.slice(-28)
  }
}

function emitHeartbeatParticle () {
  const edge = HEARTBEAT_EDGES[heartbeatEdgeIdx % HEARTBEAT_EDGES.length]
  heartbeatEdgeIdx += 1
  pushSignalParticle({
    from: edge[0],
    to: edge[1],
    type: 'heartbeat',
    size: 'small',
    label: '',
  })
}

function emitInteractiveSignal (targetId, label) {
  if (!targetId || targetId === 'P') return
  const edge = `P->${targetId}`
  const now = Date.now()
  if (now - (interactiveSignalTs[edge] || 0) < INTERACTIVE_SIGNAL_MS) return
  interactiveSignalTs[edge] = now
  pushSignalParticle({
    from: 'P',
    to: targetId,
    type: 'interactive',
    size: label ? 'large' : 'small',
    label,
  })
}

watch(() => props.externalSignals, (sigs) => {
  if (!sigs || sigs.length === 0) return
  for (const sig of sigs) {
    pushSignalParticle({
      ...sig,
      size: sig.label ? 'large' : 'small',
    })
  }
}, { deep: true })

watch(() => props.scanning, (active) => {
  if (active) {
    if (!heartbeatTimer) {
      heartbeatTimer = setInterval(() => {
        emitHeartbeatParticle()
      }, 520)
    }
  } else if (heartbeatTimer) {
    clearInterval(heartbeatTimer)
    heartbeatTimer = null
  }
}, { immediate: true })

const holographicOption = computed(() => {
  const p = agentMap['P']
  const others = agentDefs.filter(a => !a.isCenter)
  const baseLinesData = others.map(a => ({ coords: [[p.x, p.y], [a.x, a.y]] }))

  /** 不在连线上叠 ECharts 的「长尾流星」效果（易过重）；流动感交给下方 SVG 信息光球（SSE） */

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
        lineStyle: {
          color: '#a855f7',
          width: props.scanning ? 1.1 : 0.8,
          opacity: props.scanning ? 0.22 : 0.11,
          curveness: 0.15,
        },
        zlevel: 1,
      },
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
        rippleEffect: { brushType: 'stroke', scale: props.scanning ? 2.2 : 1.6, period: props.scanning ? 4.2 : 6 },
        emphasis: {
          scale: 1.25,
          itemStyle: {
            shadowBlur: 55,
          },
          label: { fontSize: 14 },
        },
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

let animFrame
onMounted(() => {
  const animate = () => {
    liveParticles.value.forEach((s) => {
      if (s.size === 'large') {
        s.progress += 0.016
      } else if (s.type === 'heartbeat') {
        s.progress += 0.013
      } else if (s.type === 'interactive') {
        s.progress += 0.018
      } else {
        s.progress += 0.012
      }
    })
    liveParticles.value = liveParticles.value.filter(s => s.progress <= 1)
    animFrame = requestAnimationFrame(animate)
  }
  animFrame = requestAnimationFrame(animate)
})

/** vue-echarts v6+ 将 ECharts API 直接挂在组件 ref 上，没有 .chart 属性 */
function resolveEchartsInstance (vchart) {
  if (!vchart) return null
  if (typeof vchart.on === 'function') return vchart
  if (vchart.chart && typeof vchart.chart.on === 'function') return vchart.chart
  if (typeof vchart.getEchartsInstance === 'function') return vchart.getEchartsInstance()
  return null
}

function agentNameFromParams (params) {
  if (!params) return null
  const d = params.data
  if (d && typeof d === 'object' && d.name) return d.name
  if (typeof params.name === 'string' && params.name) return params.name
  return null
}

function agentIdFromName (name) {
  if (!name || typeof name !== 'string') return null
  const m = name.match(/Agent-([A-Z])/)
  return m ? m[1] : null
}

watch(chartRef, (instance) => {
  const chart = resolveEchartsInstance(instance)
  if (!chart) return

  const onOver = (params) => {
    if (params.seriesType !== 'effectScatter') return
    const name = agentNameFromParams(params)
    if (!name) return
    hoveredAgent.value = name
    emit('agent-hover', agentDescriptions[name] || null)

    if (props.scanning && name !== 'Agent-P') {
      const targetId = agentIdFromName(name)
      emitInteractiveSignal(targetId, `hover ${targetId}`)
    }
  }
  const onOut = (params) => {
    if (params?.seriesType === 'effectScatter') {
      hoveredAgent.value = null
      emit('agent-hover', null)
    }
  }
  const onGlobalOut = () => {
    hoveredAgent.value = null
    emit('agent-hover', null)
  }
  chart.on('mouseover', onOver)
  chart.on('mouseout', onOut)
  chart.on('globalout', onGlobalOut)

  return () => {
    chart.off('mouseover', onOver)
    chart.off('mouseout', onOut)
    chart.off('globalout', onGlobalOut)
  }
}, { flush: 'post' })

onUnmounted(() => {
  cancelAnimationFrame(animFrame)
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer)
    heartbeatTimer = null
  }
})

const getSignalColor = (type) => {
  if (type === 'interactive') return '#22d3ee'
  if (type === 'heartbeat') return '#a78bfa'
  return type === 'neural' ? '#8B5CF6' : '#38BDF8'
}

const getSignalVisual = (type, size = 'small') => {
  if (size === 'large') {
    return {
      tail1R: 3.2,
      tail1Opacity: 0.2,
      tail2R: 2.4,
      tail2Opacity: 0.32,
      coreR1: 4.6,
      coreOpacity: 0.48,
      coreR2: 3.2,
      whiteCoreR: 1.45,
    }
  }

  if (type === 'interactive') {
    return {
      tail1R: 1.7,
      tail1Opacity: 0.09,
      tail2R: 1.3,
      tail2Opacity: 0.16,
      coreR1: 2.25,
      coreOpacity: 0.24,
      coreR2: 1.7,
      whiteCoreR: 0.95,
    }
  }

  if (type === 'heartbeat') {
    return {
      tail1R: 1.25,
      tail1Opacity: 0.05,
      tail2R: 0.95,
      tail2Opacity: 0.1,
      coreR1: 1.7,
      coreOpacity: 0.18,
      coreR2: 1.25,
      whiteCoreR: 0.7,
    }
  }

  return {
    tail1R: 2.1,
    tail1Opacity: 0.12,
    tail2R: 1.6,
    tail2Opacity: 0.18,
    coreR1: 2.8,
    coreOpacity: 0.3,
    coreR2: 2,
    whiteCoreR: 1.1,
  }
}
</script>

<template>
  <div class="w-full h-full relative perspective-1500 flex items-center justify-center overflow-hidden">

    <div class="w-[800px] h-[800px] absolute transform-3d tilt-chart" style="top: 50%; left: 50%; margin-left: -400px; margin-top: -350px;">

      <svg class="absolute inset-0 w-full h-full pointer-events-none opacity-20" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="38" fill="none" :stroke="scanning ? '#8B5CF6' : '#0EA5E9'" stroke-width="0.2" stroke-dasharray="1 2" class="transition-colors duration-1000" />
        <circle cx="50" cy="50" r="23" fill="none" :stroke="scanning ? '#c084fc' : '#8B5CF6'" stroke-width="0.1" class="transition-colors duration-1000" />
        <circle cx="50" cy="50" r="8" fill="none" :stroke="scanning ? '#8B5CF6' : '#0EA5E9'" stroke-width="0.3" stroke-dasharray="2 4" class="transition-colors duration-1000" :class="scanning ? 'animate-spin-slow' : ''" style="transform-origin: 50% 50%" />
      </svg>

      <!-- 连线由 ECharts 绘制；不在此层画线，避免与 canvas 重复且被遮挡 -->

      <div class="absolute inset-0 w-full h-full z-20 pointer-events-auto">
        <v-chart ref="chartRef" :option="holographicOption" autoresize class="h-full w-full" />
      </div>

      <!-- 必须盖在 v-chart 之上，否则全幅 canvas 会挡住「数据光球」 -->
      <svg class="agent-topology-particles absolute inset-0 w-full h-full pointer-events-none overflow-visible z-[35]" viewBox="0 0 100 100" aria-hidden="true">
        <defs>
          <filter id="agentParticleGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="1.1" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <g v-for="p in liveParticles" :key="p.id" class="packet-anim">
          <!-- 轻量尾迹：仅在运动反方向叠两枚弱圆，不做长拖尾 -->
          <circle
            :cx="p.source.x + (p.target.x - p.source.x) * Math.max(0, p.progress - 0.03)"
            :cy="p.source.y + (p.target.y - p.source.y) * Math.max(0, p.progress - 0.03)"
            :r="getSignalVisual(p.type, p.size).tail1R"
            :fill="getSignalColor(p.type)"
            :opacity="getSignalVisual(p.type, p.size).tail1Opacity"
          />
          <circle
            :cx="p.source.x + (p.target.x - p.source.x) * Math.max(0, p.progress - 0.06)"
            :cy="p.source.y + (p.target.y - p.source.y) * Math.max(0, p.progress - 0.06)"
            :r="getSignalVisual(p.type, p.size).tail2R"
            :fill="getSignalColor(p.type)"
            :opacity="getSignalVisual(p.type, p.size).tail2Opacity"
          />
          <circle
            :cx="p.source.x + (p.target.x - p.source.x) * p.progress"
            :cy="p.source.y + (p.target.y - p.source.y) * p.progress"
            :r="getSignalVisual(p.type, p.size).coreR1"
            :fill="getSignalColor(p.type)"
            :opacity="getSignalVisual(p.type, p.size).coreOpacity"
          />
          <circle
            :cx="p.source.x + (p.target.x - p.source.x) * p.progress"
            :cy="p.source.y + (p.target.y - p.source.y) * p.progress"
            :r="getSignalVisual(p.type, p.size).coreR2"
            :fill="getSignalColor(p.type)"
            filter="url(#agentParticleGlow)"
          />
          <circle
            :cx="p.source.x + (p.target.x - p.source.x) * p.progress"
            :cy="p.source.y + (p.target.y - p.source.y) * p.progress"
            :r="getSignalVisual(p.type, p.size).whiteCoreR"
            fill="#f8fafc"
            opacity="0.95"
          />
        </g>
      </svg>

      <!-- Live signal labels (briefly flash near the midpoint) -->
      <div v-for="p in liveParticles.filter(x => x.label && x.progress > 0.12 && x.progress < 0.92)" :key="'lbl-'+p.id"
           class="absolute -translate-x-1/2 -translate-y-1/2 pointer-events-none counter-tilt z-[40]"
           :style="{ left: `${p.source.x + (p.target.x - p.source.x) * p.progress}%`, top: `${p.source.y + (p.target.y - p.source.y) * p.progress}%`, opacity: p.size === 'large' ? 0.98 : 0.9 }">
        <div class="px-2 py-1 rounded bg-[#020617]/90 border font-mono shadow-lg leading-snug break-words"
             :class="p.size === 'large' ? 'max-w-[min(360px,60vw)] text-[10px] font-semibold' : 'max-w-[min(240px,42vw)] text-[9px]'"
             :style="{ borderColor: getSignalColor(p.type), color: '#e2e8f0', boxShadow: p.size === 'large' ? `0 0 14px ${getSignalColor(p.type)}80` : `0 0 8px ${getSignalColor(p.type)}40` }">
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
        LOG 数据包
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
.packet-anim { will-change: transform; }
</style>
