<template>
  <div class="report">
    <el-card class="report-card">
      <template #header>
        <div class="card-header">
          <span>报告详情</span>
          <el-button type="primary" size="small" @click="goBack">
            <el-icon><ArrowLeft /></el-icon>
            返回列表
          </el-button>
        </div>
      </template>
      
      <div v-if="loading" class="loading-container">
        <el-spinner :size="40" />
        <div class="loading-text">加载报告中...</div>
      </div>
      
      <div v-else-if="report" class="report-content">
        <!-- 基础概览 -->
        <div class="section">
          <h3>基础概览</h3>
          <div class="overview-grid">
            <div class="overview-item">
              <div class="overview-label">判定结果</div>
              <el-tag :type="getTagType(report.label)">
                {{ getTagLabel(report.label) }}
              </el-tag>
            </div>
            <div class="overview-item">
              <div class="overview-label">置信度</div>
              <div class="overview-value">{{ (report.confidence * 100).toFixed(2) }}%</div>
            </div>
            <div class="overview-item">
              <div class="overview-label">风险评分</div>
              <div class="overview-value">{{ Math.round(report.confidence * 100) }}</div>
            </div>
            <div class="overview-item">
              <div class="overview-label">处理建议</div>
              <div class="overview-value">{{ getRecommendation(report.label) }}</div>
            </div>
          </div>
          
          <div class="reason-section">
            <h4>主要致因</h4>
            <div class="reason-content">{{ report.reason || '无' }}</div>
          </div>
        </div>

        <!-- 邮件信息 -->
        <div class="section">
          <h3>邮件信息</h3>
          <el-table :data="[report.parsed]" style="width: 100%">
            <el-table-column prop="from_display_name" label="发件人名称" width="150"></el-table-column>
            <el-table-column prop="from_email" label="发件人邮箱" width="200"></el-table-column>
            <el-table-column prop="to" label="收件人" width="200"></el-table-column>
            <el-table-column prop="subject" label="主题" show-overflow-tooltip></el-table-column>
            <el-table-column prop="url_count" label="URL数量" width="80"></el-table-column>
            <el-table-column prop="attachment_count" label="附件数量" width="80"></el-table-column>
          </el-table>
        </div>

        <!-- 特征分析 -->
        <div class="section">
          <h3>特征分析</h3>
          <el-tabs type="border-card">
            <el-tab-pane label="邮件头特征">
              <el-table :data="headerFeatures" style="width: 100%">
                <el-table-column prop="name" label="特征名称" width="200"></el-table-column>
                <el-table-column prop="value" label="值"></el-table-column>
                <el-table-column prop="risk" label="风险等级" width="120">
                  <template #default="scope">
                    <el-tag :type="scope.row.risk.type">
                      {{ scope.row.risk.label }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
            </el-tab-pane>
            
            <el-tab-pane label="URL特征">
              <el-table :data="urlFeatures" style="width: 100%">
                <el-table-column prop="name" label="特征名称" width="200"></el-table-column>
                <el-table-column prop="value" label="值"></el-table-column>
                <el-table-column prop="risk" label="风险等级" width="120">
                  <template #default="scope">
                    <el-tag :type="scope.row.risk.type">
                      {{ scope.row.risk.label }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
            </el-tab-pane>
            
            <el-tab-pane label="文本特征">
              <el-table :data="textFeatures" style="width: 100%">
                <el-table-column prop="name" label="特征名称" width="200"></el-table-column>
                <el-table-column prop="value" label="值"></el-table-column>
                <el-table-column prop="risk" label="风险等级" width="120">
                  <template #default="scope">
                    <el-tag :type="scope.row.risk.type">
                      {{ scope.row.risk.label }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
            </el-tab-pane>
            
            <el-tab-pane label="附件特征">
              <el-table :data="attachmentFeatures" style="width: 100%">
                <el-table-column prop="name" label="特征名称" width="200"></el-table-column>
                <el-table-column prop="value" label="值"></el-table-column>
                <el-table-column prop="risk" label="风险等级" width="120">
                  <template #default="scope">
                    <el-tag :type="scope.row.risk.type">
                      {{ scope.row.risk.label }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
            </el-tab-pane>
            
            <el-tab-pane label="HTML特征">
              <el-table :data="htmlFeatures" style="width: 100%">
                <el-table-column prop="name" label="特征名称" width="200"></el-table-column>
                <el-table-column prop="value" label="值"></el-table-column>
                <el-table-column prop="risk" label="风险等级" width="120">
                  <template #default="scope">
                    <el-tag :type="scope.row.risk.type">
                      {{ scope.row.risk.label }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
            </el-tab-pane>
          </el-tabs>
        </div>

        <!-- URL分析 -->
        <div v-if="report.urls && report.urls.length > 0" class="section">
          <h3>URL分析</h3>
          <el-table :data="report.urls" style="width: 100%">
            <el-table-column prop="url" label="URL" show-overflow-tooltip></el-table-column>
            <el-table-column prop="risk" label="风险等级" width="120">
              <template #default="scope">
                <el-tag :type="getRiskType(scope.row.risk)">
                  {{ getRiskLabel(scope.row.risk) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="reasons" label="风险原因" show-overflow-tooltip></el-table-column>
          </el-table>
        </div>

        <!-- 附件分析 -->
        <div v-if="report.attachments && report.attachments.length > 0" class="section">
          <h3>附件分析</h3>
          <el-table :data="report.attachments" style="width: 100%">
            <el-table-column prop="filename" label="文件名" width="200"></el-table-column>
            <el-table-column prop="content_type" label="文件类型" width="150"></el-table-column>
            <el-table-column prop="size" label="大小" width="100">
              <template #default="scope">
                {{ (scope.row.size / 1024).toFixed(2) }} KB
              </template>
            </el-table-column>
            <el-table-column prop="md5" label="MD5" width="200"></el-table-column>
            <el-table-column prop="risk" label="风险等级" width="120">
              <template #default="scope">
                <el-tag :type="getRiskType(scope.row.risk)">
                  {{ getRiskLabel(scope.row.risk) }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>

        <!-- 溯源分析 -->
        <div v-if="report.traceback" class="section">
          <h3>溯源分析</h3>
          <div class="traceback-content">
            <div v-if="report.traceback.email_source" class="traceback-item">
              <h4>邮件来源</h4>
              <div class="traceback-detail">
                <div><strong>源IP:</strong> {{ report.traceback.email_source.source_ip || '未知' }}</div>
                <div v-if="report.traceback.email_source.hops && report.traceback.email_source.hops.length > 0">
                  <strong>传输路径:</strong>
                  <ul>
                    <li v-for="(hop, index) in report.traceback.email_source.hops" :key="index">
                      {{ hop.ip }} ({{ hop.hostname || '未知' }}) - {{ hop.timestamp || '未知' }}
                    </li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div v-if="report.traceback.risk_indicators && report.traceback.risk_indicators.length > 0" class="traceback-item">
              <h4>风险指标</h4>
              <ul>
                <li v-for="(indicator, index) in report.traceback.risk_indicators" :key="index">
                  {{ indicator }}
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
      
      <div v-else class="error-container">
        <el-icon class="error-icon"><Warning /></el-icon>
        <div class="error-text">报告不存在或加载失败</div>
        <el-button type="primary" @click="goBack">
          返回列表
        </el-button>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ArrowLeft, Warning } from '@element-plus/icons-vue'
import { getAlertDetail } from '../services/api'

const router = useRouter()
const route = useRoute()
const loading = ref(true)
const report = ref(null)

const headerFeatures = computed(() => {
  if (!report.value || !report.value.features) return []
  const features = report.value.features
  return [
    { name: '可疑发件人域名', value: features.is_suspicious_from_domain ? '是' : '否', risk: { type: features.is_suspicious_from_domain ? 'danger' : 'success', label: features.is_suspicious_from_domain ? '高' : '低' } },
    { name: 'SPF认证失败', value: features.spf_fail ? '是' : '否', risk: { type: features.spf_fail ? 'danger' : 'success', label: features.spf_fail ? '高' : '低' } },
    { name: 'DKIM认证失败', value: features.dkim_fail ? '是' : '否', risk: { type: features.dkim_fail ? 'danger' : 'success', label: features.dkim_fail ? '高' : '低' } },
    { name: 'DMARC认证失败', value: features.dmarc_fail ? '是' : '否', risk: { type: features.dmarc_fail ? 'danger' : 'success', label: features.dmarc_fail ? '高' : '低' } },
    { name: '发件人显示名称不匹配', value: features.from_display_name_mismatch ? '是' : '否', risk: { type: features.from_display_name_mismatch ? 'warning' : 'success', label: features.from_display_name_mismatch ? '中' : '低' } },
    { name: 'Received跳数', value: features.received_hops_count || 0, risk: { type: (features.received_hops_count || 0) > 5 ? 'warning' : 'success', label: (features.received_hops_count || 0) > 5 ? '中' : '低' } }
  ]
})

const urlFeatures = computed(() => {
  if (!report.value || !report.value.features) return []
  const features = report.value.features
  return [
    { name: '平均域名年龄', value: features.avg_domain_age_days || '未知', risk: { type: (features.avg_domain_age_days || 3650) < 30 ? 'danger' : 'success', label: (features.avg_domain_age_days || 3650) < 30 ? '高' : '低' } },
    { name: 'IP地址数量', value: features.ip_address_count || 0, risk: { type: (features.ip_address_count || 0) > 0 ? 'danger' : 'success', label: (features.ip_address_count || 0) > 0 ? '高' : '低' } },
    { name: '端口数量', value: features.port_count || 0, risk: { type: (features.port_count || 0) > 0 ? 'warning' : 'success', label: (features.port_count || 0) > 0 ? '中' : '低' } },
    { name: '短链接数量', value: features.short_url_count || 0, risk: { type: (features.short_url_count || 0) > 0 ? 'danger' : 'success', label: (features.short_url_count || 0) > 0 ? '高' : '低' } },
    { name: '可疑参数数量', value: features.suspicious_param_count || 0, risk: { type: (features.suspicious_param_count || 0) > 0 ? 'warning' : 'success', label: (features.suspicious_param_count || 0) > 0 ? '中' : '低' } }
  ]
})

const textFeatures = computed(() => {
  if (!report.value || !report.value.features) return []
  const features = report.value.features
  return [
    { name: '紧急关键词数量', value: features.urgent_keywords_count || 0, risk: { type: (features.urgent_keywords_count || 0) > 3 ? 'danger' : (features.urgent_keywords_count || 0) > 0 ? 'warning' : 'success', label: (features.urgent_keywords_count || 0) > 3 ? '高' : (features.urgent_keywords_count || 0) > 0 ? '中' : '低' } },
    { name: '金融关键词数量', value: features.financial_keywords_count || 0, risk: { type: (features.financial_keywords_count || 0) > 2 ? 'danger' : (features.financial_keywords_count || 0) > 0 ? 'warning' : 'success', label: (features.financial_keywords_count || 0) > 2 ? '高' : (features.financial_keywords_count || 0) > 0 ? '中' : '低' } },
    { name: '感叹号数量', value: features.exclamation_count || 0, risk: { type: (features.exclamation_count || 0) > 5 ? 'warning' : 'success', label: (features.exclamation_count || 0) > 5 ? '中' : '低' } },
    { name: '紧迫感评分', value: ((features.urgency_score || 0) * 100).toFixed(0) + '%', risk: { type: (features.urgency_score || 0) > 0.7 ? 'danger' : (features.urgency_score || 0) > 0.3 ? 'warning' : 'success', label: (features.urgency_score || 0) > 0.7 ? '高' : (features.urgency_score || 0) > 0.3 ? '中' : '低' } },
    { name: '大写比例', value: ((features.caps_ratio || 0) * 100).toFixed(0) + '%', risk: { type: (features.caps_ratio || 0) > 0.5 ? 'warning' : 'success', label: (features.caps_ratio || 0) > 0.5 ? '中' : '低' } }
  ]
})

const attachmentFeatures = computed(() => {
  if (!report.value || !report.value.features) return []
  const features = report.value.features
  return [
    { name: '附件数量', value: features.attachment_count || 0, risk: { type: (features.attachment_count || 0) > 3 ? 'warning' : 'success', label: (features.attachment_count || 0) > 3 ? '中' : '低' } },
    { name: '包含可疑附件', value: features.has_suspicious_attachment ? '是' : '否', risk: { type: features.has_suspicious_attachment ? 'danger' : 'success', label: features.has_suspicious_attachment ? '高' : '低' } },
    { name: '包含可执行文件', value: features.has_executable_attachment ? '是' : '否', risk: { type: features.has_executable_attachment ? 'danger' : 'success', label: features.has_executable_attachment ? '高' : '低' } },
    { name: '包含双重扩展名', value: features.has_double_extension ? '是' : '否', risk: { type: features.has_double_extension ? 'danger' : 'success', label: features.has_double_extension ? '高' : '低' } },
    { name: '沙箱检测到恶意代码', value: features.sandbox_detected ? '是' : '否', risk: { type: features.sandbox_detected ? 'danger' : 'success', label: features.sandbox_detected ? '高' : '低' } }
  ]
})

const htmlFeatures = computed(() => {
  if (!report.value || !report.value.features) return []
  const features = report.value.features
  return [
    { name: '包含HTML正文', value: features.has_html_body ? '是' : '否', risk: { type: features.has_html_body ? 'info' : 'success', label: features.has_html_body ? '中' : '低' } },
    { name: 'HTML链接数量', value: features.html_link_count || 0, risk: { type: (features.html_link_count || 0) > 10 ? 'warning' : 'success', label: (features.html_link_count || 0) > 10 ? '中' : '低' } },
    { name: '包含隐藏链接', value: features.has_hidden_links ? '是' : '否', risk: { type: features.has_hidden_links ? 'danger' : 'success', label: features.has_hidden_links ? '高' : '低' } },
    { name: '包含表单', value: features.has_form ? '是' : '否', risk: { type: features.has_form ? 'danger' : 'success', label: features.has_form ? '高' : '低' } },
    { name: '包含iframe', value: features.has_iframe ? '是' : '否', risk: { type: features.has_iframe ? 'warning' : 'success', label: features.has_iframe ? '中' : '低' } }
  ]
})

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

const getRecommendation = (label) => {
  switch (label) {
    case 'PHISHING':
      return '建议立即删除'
    case 'SUSPICIOUS':
      return '建议隔离审查'
    case 'SAFE':
      return '可安全阅读'
    default:
      return '请根据实际情况处理'
  }
}

const getRiskType = (risk) => {
  switch (risk) {
    case 'high':
      return 'danger'
    case 'medium':
      return 'warning'
    case 'low':
      return 'success'
    default:
      return 'info'
  }
}

const getRiskLabel = (risk) => {
  switch (risk) {
    case 'high':
      return '高风险'
    case 'medium':
      return '中等风险'
    case 'low':
      return '低风险'
    default:
      return '未知'
  }
}

const loadReport = async () => {
  const reportId = route.params.id
  try {
    const data = await getAlertDetail(reportId)
    report.value = data
  } catch (error) {
    console.error('加载报告失败:', error)
  } finally {
    loading.value = false
  }
}

const goBack = () => {
  router.push('/')
}

onMounted(() => {
  loadReport()
})
</script>

<style scoped>
.report {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 0;
}

.loading-text {
  margin-top: 20px;
  font-size: 16px;
  color: #606266;
}

.error-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 0;
  text-align: center;
}

.error-icon {
  font-size: 48px;
  color: #f56c6c;
  margin-bottom: 20px;
}

.error-text {
  font-size: 16px;
  color: #606266;
  margin-bottom: 20px;
}

.report-content {
  margin-top: 20px;
}

.section {
  margin-bottom: 30px;
  padding: 20px;
  background-color: #f5f7fa;
  border-radius: 8px;
}

.section h3 {
  margin-bottom: 20px;
  color: #303133;
}

.section h4 {
  margin-bottom: 15px;
  color: #409eff;
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.overview-item {
  background-color: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.overview-label {
  font-size: 14px;
  color: #606266;
  margin-bottom: 10px;
}

.overview-value {
  font-size: 18px;
  font-weight: bold;
  color: #303133;
}

.reason-section {
  background-color: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.reason-content {
  margin-top: 10px;
  line-height: 1.6;
  color: #303133;
}

.traceback-content {
  background-color: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.traceback-item {
  margin-bottom: 20px;
}

.traceback-item:last-child {
  margin-bottom: 0;
}

.traceback-detail {
  margin-top: 10px;
  line-height: 1.6;
  color: #303133;
}

.traceback-detail ul {
  margin-top: 10px;
  padding-left: 20px;
}
</style>