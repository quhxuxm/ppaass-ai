<script setup lang="ts">
import Tag from 'primevue/tag'
import ProfileEditor from '../ProfileEditor.vue'
import { useAppControllerContext } from '../../appController'

const {
  account,
  additionalPermissions,
  agentPermissionOptions,
  basePermissionOptions,
  formatExpiry,
  hasEffectivePermission,
  isAdmin,
  keyState,
  profile,
  profileSaving,
  saveMyProfile,
} = useAppControllerContext()
</script>

<template>
<div v-if="profile" class="summary-grid">
  <article class="summary-card">
    <span class="summary-icon blue"><i class="pi pi-user" /></span>
    <div><small>代理用户名</small><strong>{{ profile.username }}</strong></div>
  </article>
  <article class="summary-card">
    <span class="summary-icon green"><i class="pi pi-calendar" /></span>
    <div>
      <small>有效期</small>
      <strong>{{
        keyState === 'missing' ? '等待审批' : formatExpiry(profile.expiresAt)
      }}</strong>
    </div>
  </article>
  <article class="summary-card">
    <span class="summary-icon purple"><i class="pi pi-key" /></span>
    <div>
      <small>密钥状态</small>
      <strong>{{
        keyState === 'active'
          ? '有效'
          : keyState === 'expired'
            ? '已过期'
            : keyState === 'disabled'
              ? '已停用'
              : '尚未生成'
      }}</strong>
    </div>
  </article>
  <article class="summary-card">
    <span class="summary-icon orange"><i class="pi pi-bolt" /></span>
    <div>
      <small>代理状态</small>
      <strong>{{
        !profile.enabled
          ? '已停用'
          : keyState === 'active'
            ? '可连接'
            : keyState === 'disabled'
              ? '已停用'
              : '等待密钥'
      }}</strong>
    </div>
  </article>
</div>

<section v-if="profile" class="content-card permissions-card">
  <div class="card-heading">
    <div>
      <h2>我的权限</h2>
      <p>服务端会在每次连接和密钥操作时校验这些权限。</p>
    </div>
    <Tag
      :value="isAdmin ? '管理员全权限' : `${profile.permissions.length} 项`"
      severity="info"
      rounded
    />
  </div>
  <div class="permission-list">
    <div
      v-for="permission in basePermissionOptions"
      :key="permission.code"
      class="permission-item"
      :class="{ granted: hasEffectivePermission(permission.code) }"
    >
      <i
        :class="
          hasEffectivePermission(permission.code)
            ? 'pi pi-check-circle'
            : 'pi pi-minus-circle'
        "
      />
      <span>
        <strong>{{ permission.label }}</strong>
        <small>{{ permission.description }}</small>
      </span>
      <Tag
        :value="isAdmin ? '管理员固有' : hasEffectivePermission(permission.code) ? '已授权' : '未授权'"
        :severity="
          hasEffectivePermission(permission.code) ? 'success' : 'secondary'
        "
      />
    </div>
  </div>
  <div class="agent-permissions-overview">
    <div class="additional-permissions-heading">
      <span>
        <strong>Agent 管理权限</strong>
        <small>决定 Agent 中可使用的本机管理功能。</small>
      </span>
    </div>
    <div class="permission-list">
      <div
        v-for="permission in agentPermissionOptions"
        :key="permission.code"
        class="permission-item"
        :class="{ granted: hasEffectivePermission(permission.code) }"
      >
        <i
          :class="
            hasEffectivePermission(permission.code)
              ? 'pi pi-check-circle'
              : 'pi pi-minus-circle'
          "
        />
        <span>
          <strong>{{ permission.label }}</strong>
          <small>{{ permission.description }}</small>
        </span>
        <Tag
          :value="
            isAdmin
              ? '管理员固有'
              : hasEffectivePermission(permission.code)
                ? '已授权'
                : '未授权'
          "
          :severity="
            hasEffectivePermission(permission.code) ? 'success' : 'secondary'
          "
        />
      </div>
    </div>
  </div>
  <div class="additional-permissions">
    <div class="additional-permissions-heading">
      <span>
        <strong>附加权限</strong>
        <small>由管理员按业务需要分配，此处仅供查看。</small>
      </span>
      <Tag
        :value="`${additionalPermissions.length} 项`"
        severity="secondary"
        rounded
      />
    </div>
    <div
      v-if="additionalPermissions.length"
      class="additional-permission-tags"
      aria-label="附加权限列表"
    >
      <Tag
        v-for="permission in additionalPermissions"
        :key="permission"
        :value="permission"
        severity="info"
        rounded
      />
    </div>
    <div v-else class="additional-permissions-empty">
      <i class="pi pi-minus-circle" />
      <span>无</span>
    </div>
  </div>
</section>

<ProfileEditor
  v-if="account"
  :account="account"
  :saving="profileSaving"
  @save="saveMyProfile"
/>
</template>
