<template>
  <div class="statistics">
    <el-card class="stats-card">
      <template #header>
        <div class="card-header">
          <span>统计分析</span>
          <el-button type="primary" size="small" @click="refreshData">
            <el-icon><Refresh /></el-icon>
            刷新数据
          </el-button>
        </div>
      </template>
      
      <div class="stats-filters">
        <el-form :inline="true" :model="filterForm" class="demo-form-inline">
          <el-form-item label="时间范围">
            <el-select v-model="filterForm.days" placeholder="选择天数">
              <el-option label="7天" value="7"></el-option>
              <el-option label="14天" value="14"></el-option>
              <el-option label="30天" value="30"></el-option>
              <el-option label="90天" value="90"></el-option>
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="applyFilters">查询</el-button>
          </el-form-item>
        </el-form>
      </div>

      <div class="stats-overview">
        <el-row :gutter="20">
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-value">{{ overview.total }}</div>
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
                <div class="stat-value">{{ overview.phishing }}</div>
                <div class="stat-label">钓鱼邮件</div>
                <div class="stat-percentage">{{ getPercentage(overview.phishing, overview.total) }}%</div>
              </div>
              <div class="stat-icon danger-icon">
                <el-icon><Warning /></el-icon>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card warning">
              <div class="stat-content">
                <div class="stat-value">{{ overview.suspicious }}</div>
                <div class="stat-label">可疑邮件</div>
                <div class="stat-percentage">{{ getPercentage(overview.suspicious, overview.total) }}%</div>
              </div>
              <div class="stat-icon warning-icon">
                <el-icon><InfoFilled /></el-icon>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card success">
              <div class="stat-content">
                <div class="stat-value">{{ overview.normal }}</div>
                <div class="stat-label">正常邮件</div>
                <div class="stat-percentage">{{ getPercentage(overview.normal, overview.total) }}%</div>
              </div>
              <div class="stat-icon success-icon">
                <el-icon><Check /></el-icon>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </div>

      <div class="stats-charts">
        <el-row :gutter="20">
          <el-col :span="12">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <span>检测趋势</span>
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

        <el-row :gutter="20" style="margin-top: 20px">
          <el-col :span="12">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <span>风险因素分布</span>
                </div>
              </template>
              <div class="chart-container">
                <div ref="riskFactorsChart" class="chart"></div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="12">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <span>每日检测数量</span>
                </div>
              </template>
              <div class="chart-container">
                <div ref="dailyChart" class="chart"></div>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </div>

      <div class="stats-table">
        <el-card class="table-card">
          <template #header>
            <div class="card-header">
              <span>详细统计数据</span>
            </div>
          </template>
          <el-table :data="dailyStats" style="width: 100%">
            <el-table-column prop="day" label="日期" width="120"></el-table-column>
            <el-table-column prop="total" label="总检测" width="100"></el-table-column>
            <el-table-column prop="phishing" label="钓鱼邮件" width="120">
              <template #default="scope">
                <div class="text-danger">{{ scope.row.phishing }}</div>
              </template>
            </el-table-column>
            <el-table-column prop="suspicious" label="可疑邮件" width="120">
              <template #default="scope">
                <div class="text-warning">{{ scope.row.suspicious }}</div>
              </template>
            </el-table-column>
            <el-table-column prop="normal" label="正常邮件" width="120">
              <template #default="scope">
                <div class="text-success">{{ scope.row.normal }}</div>
              </template>
            </el-table-column>
            <el-table-column prop="phishing_rate" label="钓鱼邮件率">
              <template #default="scope">
                {{ ((scope.row.phishing / scope.row.total) * 100).toFixed(2) }}%
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, reactive } from 'vue'
import { Refresh, Message, Warning, InfoFilled, Check } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
import { getOverviewStats, getDailyStats } from '../services/api'

const filterForm = reactive({
  days: '7'
})
const overview = ref({
  total: 0,
  phishing: 0,
  suspicious: 0,
  normal: 0
})
const dailyStats = ref([])
const trendChart = ref(null)
const distributionChart = ref(null)
const riskFactorsChart = ref(null)
const dailyChart = ref(null)
let trendChartInstance = null
let distributionChartInstance = null
let riskFactorsChartInstance = null
let dailyChartInstance = null

const refreshData = async () => {
  await loadOverviewStats()
  await loadDailyStats()
  updateCharts()
}

const applyFilters = async () => {
  await loadDailyStats()
  updateCharts()
}

const loadOverviewStats = async () => {
  try {
    const data = await getOverviewStats()
    overview.value = data
  } catch (error) {
    console.error('加载概览数据失败:', error)
  }
}

const loadDailyStats = async () => {
  try {
    const data = await getDailyStats(filterForm.days)
    // 计算钓鱼邮件率
    const statsWithRate = data.map(item => ({
      ...item,
      phishing_rate: item.total > 0 ? (item.phishing / item.total) * 100 : 0
    }))
    dailyStats.value = statsWithRate
  } catch (error) {
    console.error('加载每日数据失败:', error)
  }
}

const updateCharts = () => {
  updateTrendChart()
  updateDistributionChart()
  updateRiskFactorsChart()
  updateDailyChart()
}

const updateTrendChart = () => {
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
        data: dailyStats.value.map(item => item.day)
      },
      yAxis: {
        type: 'value'
      },
      series: [
        {
          name: '钓鱼邮件',
          type: 'line',
          data: dailyStats.value.map(item => item.phishing),
          itemStyle: {
            color: '#f56c6c'
          }
        },
        {
          name: '可疑邮件',
          type: 'line',
          data: dailyStats.value.map(item => item.suspicious),
          itemStyle: {
            color: '#e6a23c'
          }
        },
        {
          name: '正常邮件',
          type: 'line',
          data: dailyStats.value.map(item => item.normal),
          itemStyle: {
            color: '#67c23a'
          }
        }
      ]
    }
    trendChartInstance.setOption(option)
  }
}

const updateDistributionChart = () => {
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
            { value: overview.value.phishing, name: '钓鱼邮件' },
            { value: overview.value.suspicious, name: '可疑邮件' },
            { value: overview.value.normal, name: '正常邮件' }
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

const updateRiskFactorsChart = () => {
  if (riskFactorsChart.value) {
    if (riskFactorsChartInstance) {
      riskFactorsChartInstance.dispose()
    }
    riskFactorsChartInstance = echarts.init(riskFactorsChart.value)
    const option = {
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'shadow'
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        data: ['邮件头', 'URL', '文本', '附件', 'HTML']
      },
      yAxis: {
        type: 'value',
        name: '风险占比 (%)'
      },
      series: [
        {
          name: '风险占比',
          type: 'bar',
          data: [25, 35, 20, 15, 5],
          itemStyle: {
            color: function(params) {
              const colors = ['#f56c6c', '#e6a23c', '#409eff', '#67c23a', '#909399']
              return colors[params.dataIndex]
            }
          }
        }
      ]
    }
    riskFactorsChartInstance.setOption(option)
  }
}

const updateDailyChart = () => {
  if (dailyChart.value) {
    if (dailyChartInstance) {
      dailyChartInstance.dispose()
    }
    dailyChartInstance = echarts.init(dailyChart.value)
    const option = {
      tooltip: {
        trigger: 'axis'
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
        data: dailyStats.value.map(item => item.day)
      },
      yAxis: {
        type: 'value'
      },
      series: [
        {
          name: '每日检测数量',
          type: 'bar',
          data: dailyStats.value.map(item => item.total),
          itemStyle: {
            color: '#409eff'
          }
        }
      ]
    }
    dailyChartInstance.setOption(option)
  }
}

const getPercentage = (value, total) => {
  if (total === 0) return 0
  return ((value / total) * 100).toFixed(1)
}

onMounted(async () => {
  await refreshData()
  window.addEventListener('resize', updateCharts)
})
</script>

<style scoped>
.statistics {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stats-filters {
  margin-bottom: 20px;
}

.stats-overview {
  margin-bottom: 30px;
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
  margin-bottom: 5px;
}

.stat-percentage {
  font-size: 12px;
  color: #606266;
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

.stats-charts {
  margin-bottom: 30px;
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

.stats-table {
  margin-top: 20px;
}
</style>