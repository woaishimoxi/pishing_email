import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000
})

// 请求拦截器
api.interceptors.request.use(
  config => {
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  response => {
    return response.data
  },
  error => {
    console.error('API请求错误:', error)
    return Promise.reject(error)
  }
)

// 检测相关API
export const analyzeEmail = (email) => {
  return api.post('/analyze', { email })
}

export const uploadEmail = (file) => {
  const formData = new FormData()
  formData.append('file', file)
  return api.post('/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  })
}

// 统计相关API
export const getOverviewStats = () => {
  return api.get('/stats/overview')
}

export const getDailyStats = (days = 7) => {
  return api.get(`/stats/daily?days=${days}`)
}

// 告警相关API
export const getAlerts = (page = 1, perPage = 20, label = null) => {
  let url = `/alerts?page=${page}&per_page=${perPage}`
  if (label) {
    url += `&label=${label}`
  }
  return api.get(url)
}

export const getAlertDetail = (alertId) => {
  return api.get(`/alert/${alertId}`)
}

export const deleteAlert = (alertId) => {
  return api.delete(`/alerts/${alertId}`)
}

export const batchDeleteAlerts = (ids) => {
  return api.delete('/alerts/batch', { data: { ids } })
}

// 配置相关API
export const getConfig = () => {
  return api.get('/config')
}

export const updateConfig = (config) => {
  return api.post('/config', config)
}

export const testApiConnection = () => {
  return api.get('/config/test')
}

// 系统相关API
export const getSystemStatus = () => {
  return api.get('/system/status')
}

export const shutdownSystem = () => {
  return api.post('/system/shutdown')
}

// 辅助函数
export const getRecentAlerts = async () => {
  try {
    const response = await getAlerts(1, 10)
    return response.alerts || []
  } catch (error) {
    console.error('获取最近检测记录失败:', error)
    return []
  }
}

export default api