<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import {
  Activity,
  Cpu,
  Database,
  Zap,
  Radio,
  ShieldAlert,
  Network,
  Crosshair,
  FlaskConical,
  Swords,
  Trophy,
} from 'lucide-vue-next'
import { fetchHealth } from './api'

const router = useRouter()
const route = useRoute()

const timeString = ref('')
const systemMetrics = ref({
  health: 'OPTIMAL',
  latency: 124,
  activeAgents: 6,
  templates: 0,
  memoryRecords: 0,
})

const navItems = [
  { name: 'nexus', path: '/', icon: Network, label: 'NEXUS', desc: 'Agent 神经中枢' },
  { name: 'mission', path: '/mission', icon: Crosshair, label: 'MISSION', desc: '扫描指挥室' },
  { name: 'forensics', path: '/forensics', icon: FlaskConical, label: 'FORENSICS', desc: '证据实验室' },
  { name: 'arsenal', path: '/arsenal', icon: Swords, label: 'ARSENAL', desc: '武器库' },
  { name: 'arena', path: '/arena', icon: Trophy, label: 'ARENA', desc: '竞技场' },
]

const activeNav = computed(() => {
  const p = route.path
  if (p === '/') return 'nexus'
  if (p.startsWith('/mission')) return 'mission'
  if (p.startsWith('/forensics')) return 'forensics'
  if (p.startsWith('/arsenal')) return 'arsenal'
  if (p.startsWith('/arena')) return 'arena'
  return 'nexus'
})

const sidebarExpanded = ref(false)

let timer, apiTimer
onMounted(async () => {
  const updateTime = () => {
    const now = new Date()
    timeString.value =
      now.toLocaleTimeString('zh-CN', { hour12: false }) +
      '.' +
      now.getMilliseconds().toString().padStart(3, '0').slice(0, 3)
  }
  timer = setInterval(updateTime, 47)
  updateTime()

  const doFetch = async () => {
    try {
      const start = performance.now()
      const data = await fetchHealth()
      systemMetrics.value.templates = data.template_count
      systemMetrics.value.memoryRecords = data.memory_count
      systemMetrics.value.latency = Math.floor(performance.now() - start)
      systemMetrics.value.health = 'OPTIMAL'
    } catch {
      systemMetrics.value.health = 'DEGRADED'
    }
  }
  doFetch()
  apiTimer = setInterval(doFetch, 8000)
})

onUnmounted(() => {
  clearInterval(timer)
  clearInterval(apiTimer)
})
</script>

<template>
  <div class="h-screen w-screen flex flex-col text-gray-300 font-sans relative bg-cyber-dark overflow-hidden">
    <div class="absolute top-1/4 left-1/4 w-96 h-96 bg-argus-purple/5 rounded-full blur-[120px] pointer-events-none"></div>
    <div class="absolute bottom-1/4 right-1/4 w-96 h-96 bg-safe-blue/5 rounded-full blur-[120px] pointer-events-none"></div>

    <!-- Topbar -->
    <header class="h-12 border-b border-white/5 flex items-center justify-between px-5 z-30 bg-[#020617]/90 backdrop-blur-md shrink-0">
      <div class="flex items-center gap-3 cursor-pointer group" @click="router.push('/')">
        <div class="w-8 h-8 rounded-lg bg-argus-purple/20 flex items-center justify-center border border-argus-purple/50 group-hover:bg-argus-purple/30 group-hover:shadow-[0_0_12px_rgba(139,92,246,0.4)] transition-all duration-300">
          <ShieldAlert class="w-4.5 h-4.5 text-argus-purple group-hover:text-white transition-colors" />
        </div>
        <h1 class="argus-logo text-xl font-black tracking-[0.25em] font-mono select-none">
          <span class="argus-letter" style="--i:0">A</span><span class="argus-letter" style="--i:1">R</span><span class="argus-letter" style="--i:2">G</span><span class="argus-letter" style="--i:3">U</span><span class="argus-letter" style="--i:4">S</span>
        </h1>
      </div>

      <div class="flex gap-5 items-center text-[11px] font-mono">
        <div class="flex items-center gap-1.5" title="系统健康度">
          <Activity class="w-3.5 h-3.5" :class="systemMetrics.health === 'OPTIMAL' ? 'text-green-400' : 'text-yellow-400'" />
          <span class="text-gray-500">SYS</span>
          <span :class="systemMetrics.health === 'OPTIMAL' ? 'text-green-400' : 'text-yellow-400'">{{ systemMetrics.health }}</span>
        </div>
        <div class="flex items-center gap-1.5">
          <Radio class="w-3.5 h-3.5 text-safe-blue animate-pulse" />
          <span class="text-gray-500">LAT</span>
          <span class="text-safe-blue w-8 text-right">{{ systemMetrics.latency }}ms</span>
        </div>
        <div class="flex items-center gap-1.5">
          <Database class="w-3.5 h-3.5 text-neon-blue" />
          <span class="text-gray-500">QL</span>
          <span class="text-neon-blue w-6 text-right">{{ systemMetrics.templates }}</span>
        </div>
        <div class="flex items-center gap-1.5">
          <Zap class="w-3.5 h-3.5 text-neon-blue" />
          <span class="text-gray-500">MEM</span>
          <span class="text-neon-blue w-8 text-right">{{ systemMetrics.memoryRecords }}</span>
        </div>
        <div class="flex items-center gap-1.5">
          <Cpu class="w-3.5 h-3.5 text-argus-purple" />
          <span class="text-gray-500">AGT</span>
          <span class="text-argus-purple">{{ systemMetrics.activeAgents }}</span>
        </div>
        <div class="h-3 w-px bg-white/10"></div>
        <div class="text-neon-purple tracking-widest min-w-[100px] text-right font-bold">{{ timeString }}</div>
      </div>
    </header>

    <div class="flex flex-1 overflow-hidden z-10">
      <!-- Sidebar -->
      <aside
        class="border-r border-white/5 flex flex-col items-center py-4 gap-1 shrink-0 bg-[#0f172a]/60 backdrop-blur-md transition-all duration-300 z-20"
        :class="sidebarExpanded ? 'w-44' : 'w-14'"
        @mouseenter="sidebarExpanded = true"
        @mouseleave="sidebarExpanded = false"
      >
        <router-link
          v-for="item in navItems"
          :key="item.name"
          :to="item.path"
          class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg mx-1 transition-all duration-200 group relative"
          :class="activeNav === item.name
            ? 'bg-argus-purple/15 text-white'
            : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'"
        >
          <div class="relative shrink-0 flex items-center justify-center w-8 h-8">
            <component :is="item.icon" class="w-5 h-5 transition-colors" />
            <div
              v-if="activeNav === item.name"
              class="absolute -left-3 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-argus-purple rounded-r-full shadow-[0_0_8px_rgba(139,92,246,0.8)]"
            ></div>
          </div>
          <transition name="fade">
            <div v-if="sidebarExpanded" class="flex flex-col overflow-hidden">
              <span class="text-[11px] font-mono font-bold tracking-wider whitespace-nowrap">{{ item.label }}</span>
              <span class="text-[9px] text-gray-500 whitespace-nowrap">{{ item.desc }}</span>
            </div>
          </transition>
        </router-link>
      </aside>

      <!-- Main Content -->
      <main class="flex-1 relative overflow-hidden">
        <router-view v-slot="{ Component }">
          <transition name="page" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </main>
    </div>
  </div>
</template>

<style>
.fade-enter-active, .fade-leave-active { transition: opacity 0.15s ease; }
.fade-enter-from, .fade-leave-to { opacity: 0; }

.page-enter-active { transition: opacity 0.25s ease, transform 0.25s ease; }
.page-leave-active { transition: opacity 0.15s ease; }
.page-enter-from { opacity: 0; transform: translateY(8px); }
.page-leave-to { opacity: 0; }

/* ARGUS Logo */
.argus-logo {
  position: relative;
  line-height: 1;
}
.argus-letter {
  display: inline-block;
  background: linear-gradient(135deg, #c084fc 0%, #a855f7 30%, #38bdf8 70%, #818cf8 100%);
  background-size: 200% 200%;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: argusShimmer 4s ease-in-out infinite;
  animation-delay: calc(var(--i) * 0.15s);
  text-shadow: none;
  filter: drop-shadow(0 0 6px rgba(139, 92, 246, 0.4));
}
.group:hover .argus-letter {
  filter: drop-shadow(0 0 12px rgba(139, 92, 246, 0.7));
  animation-duration: 2s;
}
@keyframes argusShimmer {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}
</style>
