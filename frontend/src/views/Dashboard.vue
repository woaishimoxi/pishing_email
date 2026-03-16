<template>
  <div class="dashboard">
    <el-card class="welcome-card">
      <template #header>
        <div class="card-header">
          <span>系统概览</span>
          <el-button type="primary" size="small" @click="refreshData">
            <el-icon><Refresh /></el-icon>
            刷新数据
          </el-button>
        </div>
      </template>
      <div class="stats-banner">
        <el-row :gutter="20">
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-value">{{ stats.total }}</div>
                <div class="stat-label">总邮件数</div>
              </div>
              <div class="stat-icon total-icon">
                <el-icon><Message /></el-icon>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card danger">
              <div class="stat-content">
                <div class="stat-value">{{ stats.phishing }}</div>
                <div class="stat-label">钓鱼邮件</div>
              </div>
              <div class="stat-icon danger-icon">
                <el-icon><Warning /></el-icon>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card warning">
              <div class="stat-content">
                <div class="stat-value">{{ stats.suspicious }}</div>
                <div class="stat-label">可疑邮件</div>
              </div>
              <div class="stat-icon warning-icon">
                <el-icon><InfoFilled /></el-icon>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card success">
              <div class="stat-content">
                <div class="stat-value">{{ stats.today }}</div>
                <div class="stat-label">今日检测</div>
              </div>
              <div class="stat-icon success-icon">
                <el-icon><Calendar /></el-icon>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </div>
    </el-card>

    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>近7天检测趋势</span>
            </div>
          </template>
          <div class="chart-container">
            <div ref="trendChart" class="chart"></div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>邮件类型分布</span>
            </div>
          </template>
          <div class="chart-container">
            <div ref="distributionChart" class="chart"></div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card class="recent-alerts" style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>最近检测记录</span>
          <el-button type="primary" size="small" @click="goToDetection">
            <el-icon><Plus /></el-icon>
            开始检测
          </el-button>
        </div>
      </template>
      <el-table :data="recentAlerts" style="width: 100%">
        <el-table-column prop="from" label="发件人" width="200"></el-table-column>
        <el-table-column prop="subject" label="主题" show-overflow-tooltip></el-table-column>
        <el-table-column prop="label" label="判定结果" width="100">
          <template #default="scope">
            <el-tag :type="getTagType(scope.row.label)">
              {{ getTagLabel(scope.row.label) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="confidence" label="置信度" width="100">
          <template #default="scope">
            {{ (scope.row.confidence * 100).toFixed(0) }}%
          </template>
        </el-table-column>
        <el-table-column prop="detection_time" label="检测时间" width="180"></el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="scope">
            <el-button type="primary" size="small" @click="viewReport(scope.row.id)">
              查看
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Refresh, Message, Warning, InfoFilled, Calendar, Plus } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
import { getOverviewStats, getRecentAlerts } from '../services/api'

const router = useRouter()
const stats = ref({
  total: 0,
  phishing: 0,
  suspicious: 0,
  normal: 0,
  today: 0
})
const recentAlerts = ref([])
const trendChart = ref(null)
const distributionChart = ref(null)
let trendChartInstance = null
let distributionChartInstance = null

const refreshData = async () => {
  await loadStats()
  await loadRecentAlerts()
  updateCharts()
}

const loadStats = async () => {
  try {
    const data = await getOverviewStats()
    stats.value = data
  } catch (error) {
    console.error('加载统计数据失败:', error)
  }
}

const loadRecentAlerts = async () => {
  try {
    const data = await getRecentAlerts()
    recentAlerts.value = data
  } catch (error) {
    console.error('加载最近检测记录失败:', error)
  }
}

const updateCharts = () => {
  if (trendChart.value) {
    if (trendChartInstance) {
      trendChartInstance.dispose()
    }
    trendChartInstance = echarts.init(trendChart.value)
    const option = {
      tooltip: {
        trigger: 'axis'
      },
      legend: {
        data: ['钓鱼邮件', '可疑邮件', '正常邮件']
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: stats.value.trend?.map(item => item.day) || []
      },
      yAxis: {
        type: 'value'
      },
      series: [
        {
          name: '钓鱼邮件',
          type: 'line',
          stack: 'Total',
          data: stats.value.trend?.map(item => item.phish_count) || [],
          itemStyle: {
            color: '#f56c6c'
          }
        },
        {
          name: '可疑邮件',
          type: 'line',
          stack: 'Total',
          data: stats.value.trend?.map(item => item.suspicious_count) || [],
          itemStyle: {
            color: '#e6a23c'
          }
        },
        {
          name: '正常邮件',
          type: 'line',
          stack: 'Total',
          data: stats.value.trend?.map(item => item.safe_count) || [],
          itemStyle: {
            color: '#67c23a'
          }
        }
      ]
    }
    trendChartInstance.setOption(option)
  }

  if (distributionChart.value) {
    if (distributionChartInstance) {
      distributionChartInstance.dispose()
    }
    distributionChartInstance = echarts.init(distributionChart.value)
    const option = {
      tooltip: {
        trigger: 'item'
      },
      legend: {
        orient: 'vertical',
        left: 'left'
      },
      series: [
        {
          name: '邮件类型',
          type: 'pie',
          radius: '60%',
          data: [
            { value: stats.value.phishing, name: '钓鱼邮件' },
            { value: stats.value.suspicious, name: '可疑邮件' },
            { value: stats.value.normal, name: '正常邮件' }
          ],
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: 'rgba(0, 0, 0, 0.5)'
            }
          }
        }
      ]
    }
    distributionChartInstance.setOption(option)
  }
}

const getTagType = (label) => {
  switch (label) {
    case 'PHISHING':
      return 'danger'
    case 'SUSPICIOUS':
      return 'warning'
    case 'SAFE':
      return 'success'
    default:
      return 'info'
  }
}

const getTagLabel = (label) => {
  switch (label) {
    case 'PHISHING':
      return '钓鱼邮件'
    case 'SUSPICIOUS':
      return '可疑邮件'
    case 'SAFE':
      return '正常邮件'
    default:
      return label
  }
}

const viewReport = (id) => {
  router.push(`/report/${id}`)
}

const goToDetection = () => {
  router.push('/detection')
}

onMounted(async () => {
  await refreshData()
  window.addEventListener('resize', updateCharts)
})
</script>

<style scoped>
.dashboard {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stats-banner {
  margin-top: 20px;
}

.stat-card {
  position: relative;
  overflow: hidden;
  transition: all 0.3s ease;
}

.stat-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
}

.stat-content {
  padding: 20px;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  margin-bottom: 10px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
}

.stat-icon {
  position: absolute;
  top: 20px;
  right: 20px;
  font-size: 40px;
  opacity: 0.1;
}

.total-icon {
  color: #409eff;
}

.danger-icon {
  color: #f56c6c;
}

.warning-icon {
  color: #e6a23c;
}

.success-icon {
  color: #67c23a;
}

.chart-card {
  height: 400px;
}

.chart-container {
  height: 340px;
}

.chart {
  width: 100%;
  height: 100%;
}

.recent-alerts {
  margin-top: 20px;
}
</style>