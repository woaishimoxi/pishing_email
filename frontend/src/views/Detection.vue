<template>
  <div class="detection">
    <el-card class="detection-card">
      <template #header>
        <div class="card-header">
          <span>邮件检测</span>
        </div>
      </template>
      
      <el-tabs v-model="activeTab">
        <el-tab-pane label="粘贴邮件内容" name="paste">
          <el-form :model="form" label-width="80px">
            <el-form-item label="邮件内容">
              <el-input
                v-model="form.email"
                type="textarea"
                :rows="10"
                placeholder="请粘贴原始邮件内容..."
                maxlength="100000"
                show-word-limit
              ></el-input>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="startDetection" :loading="loading">
                <el-icon><Search /></el-icon>
                开始检测
              </el-button>
              <el-button @click="resetForm">
                重置
              </el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>
        
        <el-tab-pane label="上传邮件文件" name="upload">
          <el-upload
            class="upload-demo"
            drag
            action="/api/upload"
            :on-success="handleUploadSuccess"
            :on-error="handleUploadError"
            :before-upload="beforeUpload"
            :show-file-list="false"
            :loading="loading"
          >
            <el-icon class="el-icon--upload"><Upload /></el-icon>
            <div class="el-upload__text">
              将文件拖到此处，或 <em>点击上传</em>
            </div>
            <template #tip>
              <div class="el-upload__tip">
                支持上传 .eml 或 .msg 格式的邮件文件
              </div>
            </template>
          </el-upload>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 加载中遮罩 -->
    <div v-if="loading" class="loading-overlay">
      <div class="loading-content">
        <el-spinner :size="40" />
        <div class="loading-text">{{ loadingText }}</div>
        <el-progress :percentage="loadingProgress" :stroke-width="15" :show-text="false" style="width: 80%; margin-top: 20px" />
      </div>
    </div>

    <!-- 检测结果 -->
    <el-card v-if="result" class="result-card" style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>检测结果</span>
          <el-button type="primary" size="small" @click="viewReport">
            查看详细报告
          </el-button>
        </div>
      </template>
      
      <div class="result-content">
        <div class="result-overview">
          <div class="result-item">
            <span class="result-label">判定结果:</span>
            <el-tag :type="getTagType(result.label)">
              {{ getTagLabel(result.label) }}
            </el-tag>
          </div>
          <div class="result-item">
            <span class="result-label">置信度:</span>
            <span class="result-value">{{ (result.confidence * 100).toFixed(2) }}%</span>
          </div>
          <div class="result-item">
            <span class="result-label">主要致因:</span>
            <span class="result-value">{{ result.reason || '无' }}</span>
          </div>
          <div class="result-item">
            <span class="result-label">处理建议:</span>
            <span class="result-value">{{ getRecommendation(result.label) }}</span>
          </div>
        </div>

        <div class="result-details">
          <h4>邮件信息</h4>
          <el-table :data="[result.parsed]" style="width: 100%">
            <el-table-column prop="from_display_name" label="发件人名称" width="150"></el-table-column>
            <el-table-column prop="from_email" label="发件人邮箱" width="200"></el-table-column>
            <el-table-column prop="to" label="收件人" width="200"></el-table-column>
            <el-table-column prop="subject" label="主题" show-overflow-tooltip></el-table-column>
            <el-table-column prop="url_count" label="URL数量" width="80"></el-table-column>
            <el-table-column prop="attachment_count" label="附件数量" width="80"></el-table-column>
          </el-table>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { Search, Upload } from '@element-plus/icons-vue'
import { analyzeEmail } from '../services/api'

const router = useRouter()
const activeTab = ref('paste')
const loading = ref(false)
const loadingText = ref('正在分析邮件...')
const loadingProgress = ref(0)
const form = reactive({
  email: ''
})
const result = ref(null)

const startDetection = async () => {
  if (!form.email) {
    ElMessage.warning('请输入邮件内容')
    return
  }

  loading.value = true
  loadingProgress.value = 0
  
  // 模拟进度
  const progressInterval = setInterval(() => {
    if (loadingProgress.value < 90) {
      loadingProgress.value += 10
      if (loadingProgress.value <= 30) {
        loadingText.value = '正在解析邮件...'
      } else if (loadingProgress.value <= 60) {
        loadingText.value = '正在提取特征...'
      } else {
        loadingText.value = '正在分析风险...'
      }
    }
  }, 200)

  try {
    const data = await analyzeEmail(form.email)
    result.value = data
    loadingProgress.value = 100
    loadingText.value = '分析完成'
    
    // 延迟关闭加载
    setTimeout(() => {
      loading.value = false
      clearInterval(progressInterval)
    }, 500)
  } catch (error) {
    ElMessage.error('分析失败: ' + error.message)
    loading.value = false
    clearInterval(progressInterval)
  }
}

const resetForm = () => {
  form.email = ''
  result.value = null
}

const handleUploadSuccess = (response) => {
  result.value = response
  loading.value = false
  ElMessage.success('文件上传成功')
}

const handleUploadError = (error) => {
  ElMessage.error('文件上传失败: ' + error.message)
  loading.value = false
}

const beforeUpload = (file) => {
  const allowedTypes = ['.eml', '.msg']
  const ext = file.name.substring(file.name.lastIndexOf('.'))
  if (!allowedTypes.includes(ext.toLowerCase())) {
    ElMessage.error('只支持 .eml 或 .msg 格式的文件')
    return false
  }
  loading.value = true
  return true
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

const viewReport = () => {
  // 这里需要根据实际情况生成报告ID并跳转
  // 暂时使用模拟ID
  router.push('/report/1')
}
</script>

<style scoped>
.detection {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.loading-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(255, 255, 255, 0.9);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.loading-content {
  text-align: center;
  padding: 40px;
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.loading-text {
  margin-top: 20px;
  font-size: 16px;
  color: #606266;
}

.result-card {
  margin-top: 20px;
}

.result-content {
  margin-top: 20px;
}

.result-overview {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
  margin-bottom: 30px;
  padding: 20px;
  background-color: #f5f7fa;
  border-radius: 8px;
}

.result-item {
  display: flex;
  align-items: center;
  gap: 10px;
}

.result-label {
  font-weight: 600;
  color: #606266;
}

.result-value {
  color: #303133;
}

.result-details {
  margin-top: 20px;
}

.result-details h4 {
  margin-bottom: 15px;
  color: #303133;
}
</style>