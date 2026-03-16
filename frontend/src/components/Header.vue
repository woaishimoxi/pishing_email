<template>
  <el-header height="60px" class="header">
    <div class="logo">
      <h1>钓鱼邮件检测与溯源系统</h1>
    </div>
    <div class="user-info">
      <el-dropdown>
        <span class="user-name">管理员</span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item>个人中心</el-dropdown-item>
            <el-dropdown-item>系统设置</el-dropdown-item>
            <el-dropdown-item divided @click="logout">退出登录</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>
  </el-header>
</template>

<script setup>
import { ElMessage } from 'element-plus'

const logout = () => {
  ElMessage.success('退出登录成功')
}
</script>

<style scoped>
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background-color: #001529;
  color: white;
  padding: 0 20px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
}

.logo h1 {
  font-size: 20px;
  margin: 0;
  font-weight: 600;
}

.user-info {
  display: flex;
  align-items: center;
}

.user-name {
  cursor: pointer;
  font-size: 14px;
}

.user-name:hover {
  color: #1890ff;
}
</style>