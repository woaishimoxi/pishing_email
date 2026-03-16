<template>
  <div class="app-container">
    <el-container style="min-height: 100vh">
      <Header />
      <el-container>
        <Sidebar />
        <el-main class="main-content">
          <router-view v-slot="{ Component }">
            <transition name="fade" mode="out-in">
              <component :is="Component" />
            </transition>
          </router-view>
        </el-main>
      </el-container>
      <el-footer height="40px" class="footer">
        <div class="footer-content">
          © 2026 钓鱼邮件检测与溯源系统 | 版本 v1.3.0
        </div>
      </el-footer>
    </el-container>
  </div>
</template>

<script setup>
import Header from './components/Header.vue'
import Sidebar from './components/Sidebar.vue'
</script>

<style scoped>
.app-container {
  width: 100%;
  height: 100vh;
}

.main-content {
  padding: 20px;
  background-color: #f0f2f5;
  overflow-y: auto;
}

.footer {
  background-color: #f5f7fa;
  border-top: 1px solid #e4e7ed;
  padding: 0;
}

.footer-content {
  text-align: center;
  line-height: 40px;
  color: #909399;
  font-size: 14px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>