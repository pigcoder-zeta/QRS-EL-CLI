import { reactive, watch } from 'vue'

const STORAGE_KEY = 'argus_active_task'

export const scanStore = reactive({
  activeTaskId: localStorage.getItem(STORAGE_KEY) || null,
  status: localStorage.getItem(STORAGE_KEY) ? 'running' : 'idle',
  resultFile: null,
})

watch(() => scanStore.activeTaskId, (val) => {
  if (val) localStorage.setItem(STORAGE_KEY, val)
  else localStorage.removeItem(STORAGE_KEY)
})

export function setActiveTask(taskId) {
  scanStore.activeTaskId = taskId
  scanStore.status = 'running'
  scanStore.resultFile = null
}

export function clearActiveTask() {
  scanStore.activeTaskId = null
  scanStore.status = 'idle'
  scanStore.resultFile = null
}

export function completeTask(resultFile) {
  scanStore.status = 'completed'
  scanStore.resultFile = resultFile || null
  localStorage.removeItem(STORAGE_KEY)
}

export function failTask() {
  scanStore.status = 'error'
  localStorage.removeItem(STORAGE_KEY)
}
