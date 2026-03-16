<template>
  <el-aside width="200px" class="sidebar">
    <el-menu
      :default-active="activeMenu"
      class="sidebar-menu"
      router
      unique-opened
    >
      <el-menu-item index="/">
        <el-icon><House /></el-icon>
        <span>仪表盘</span>
      </el-menu-item>
      <el-menu-item index="/detection">
        <el-icon><Search /></el-icon>
        <span>邮件检测</span>
      </el-menu-item>
      <el-menu-item index="/report">
        <el-icon><Document /></el-icon>
        <span>检测报告</span>
      </el-menu-item>
      <el-menu-item index="/statistics">
        <el-icon><DataAnalysis /></el-icon>
        <span>统计分析</span>
      </el-menu-item>
    </el-menu>
  </el-aside>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { House, Search, Document, DataAnalysis } from '@element-plus/icons-vue'

const route = useRoute()
const activeMenu = computed(() => route.path)
</script>

<style scoped>
.sidebar {
  background-color: #001529;
  height: calc(100vh - 60px);
  box-shadow: 2px 0 8px rgba(0, 0, 0, 0.15);
}

.sidebar-menu {
  border-right: none;
  height: 100%;
}

:deep(.el-menu-item) {
  color: rgba(255, 255, 255, 0.65);
  height: 60px;
  line-height: 60px;
  margin: 0;
}

:deep(.el-menu-item:hover) {
  background-color: rgba(255, 255, 255, 0.1);
  color: #fff;
}

:deep(.el-menu-item.is-active) {
  background-color: #1890ff;
  color: #fff;
}

:deep(.el-icon) {
  margin-right: 10px;
}
</style>