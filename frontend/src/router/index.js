import { createRouter, createWebHistory } from 'vue-router'

import NexusView from '../views/NexusView.vue'
import MissionView from '../views/MissionView.vue'
import MissionLiveView from '../views/MissionLiveView.vue'
import ForensicsView from '../views/ForensicsView.vue'
import ForensicsDetailView from '../views/ForensicsDetailView.vue'
import ArsenalView from '../views/ArsenalView.vue'
import ArenaView from '../views/ArenaView.vue'

const routes = [
  { path: '/', name: 'nexus', component: NexusView },
  { path: '/mission', name: 'mission', component: MissionView },
  { path: '/mission/:id', name: 'mission-live', component: MissionLiveView, props: true },
  { path: '/forensics', name: 'forensics', component: ForensicsView },
  { path: '/forensics/:id', name: 'forensics-detail', component: ForensicsDetailView, props: true },
  { path: '/arsenal', name: 'arsenal', component: ArsenalView },
  { path: '/arena', name: 'arena', component: ArenaView },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
