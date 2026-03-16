import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('../views/Dashboard.vue'),
    meta: {
      title: '仪表盘'
    }
  },
  {
    path: '/detection',
    name: 'Detection',
    component: () => import('../views/Detection.vue'),
    meta: {
      title: '邮件检测'
    }
  },
  {
    path: '/report/:id',
    name: 'Report',
    component: () => import('../views/Report.vue'),
    meta: {
      title: '报告详情'
    }
  },
  {
    path: '/statistics',
    name: 'Statistics',
    component: () => import('../views/Statistics.vue'),
    meta: {
      title: '统计分析'
    }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from, next) => {
  document.title = to.meta.title || '钓鱼邮件检测与溯源系统'
  next()
})

export default router