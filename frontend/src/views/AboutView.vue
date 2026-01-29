<script setup lang="ts">
import { useI18n } from 'vue-i18n'

import logo from '@/assets/logo'
import { RestartApp, BrowserOpenURL } from '@/bridge'
import { useAppStore, useEnvStore } from '@/stores'
import { APP_TITLE, APP_VERSION, PROJECT_URL, TG_GROUP, TG_CHANNEL, message } from '@/utils'

const { t } = useI18n()
const envStore = useEnvStore()
const appStore = useAppStore()

const handleRestartApp = async () => {
  try {
    await RestartApp()
  } catch (error: any) {
    message.error(error)
  }
}

appStore.checkForUpdates()
</script>

<template>
  <div class="h-full flex flex-col justify-center items-center py-12 relative">
    <div
      class="flex flex-col items-center bg-white/50 dark:bg-gray-800/50 backdrop-blur-xl p-12 rounded-3xl shadow-2xl border border-white/20 dark:border-gray-700/50 w-full max-w-md transition-all duration-500 hover:shadow-green-500/10"
    >
      <div class="relative group">
        <img
          :src="logo"
          class="w-32 h-32 mb-6 drop-shadow-2xl transition-transform duration-500 group-hover:scale-110"
          draggable="false"
        />
        <div
          class="absolute inset-0 bg-green-500/20 blur-3xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-700 -z-10"
        ></div>
      </div>

      <h1
        class="text-3xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-green-600 to-teal-500 dark:from-green-400 dark:to-teal-300 mb-2 tracking-tight"
      >
        {{ APP_TITLE }}
      </h1>

      <div class="mb-10 w-full flex flex-col items-center gap-4">
        <Button
          v-if="appStore.restartable"
          icon="restartApp"
          type="primary"
          class="rounded-full px-8 h-10 shadow-lg shadow-green-500/30 w-full max-w-xs font-bold tracking-wide"
          @click="handleRestartApp"
        >
          {{ t('about.restart') }}
        </Button>

        <template v-else>
          <div
            class="px-5 py-1.5 bg-gray-100/80 dark:bg-gray-700/80 rounded-full text-sm font-mono text-gray-600 dark:text-gray-300 cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors flex items-center gap-2 border border-transparent hover:border-green-500/30"
            @click="appStore.checkForUpdates(true)"
            title="Check for updates"
          >
            <span
              v-if="appStore.checkForUpdatesLoading"
              class="w-2 h-2 bg-green-500 rounded-full animate-ping"
            ></span>
            <span v-else class="text-green-500">v</span>
            {{ APP_VERSION }}
          </div>

          <Button
            v-if="appStore.updatable"
            :loading="appStore.downloading"
            type="primary"
            class="mt-2 rounded-full px-6 h-10 shadow-lg shadow-green-500/20 w-full max-w-xs animate-pulse"
            @click="appStore.downloadApp"
          >
            <span class="flex items-center gap-2">
              <Icon icon="download" />
              {{ t('about.new') }}: {{ appStore.remoteVersion }}
            </span>
          </Button>
        </template>
      </div>

      <div class="flex gap-6 mt-2">
        <div
          class="p-3 rounded-2xl bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-600 cursor-pointer transition-all duration-300 hover:scale-110 shadow-sm hover:shadow-md group"
          @click="BrowserOpenURL(PROJECT_URL)"
          title="GitHub"
        >
          <Icon icon="github" class="text-2xl text-gray-600 dark:text-gray-300 group-hover:text-black dark:group-hover:text-white transition-colors" />
        </div>
        
        <div
          v-if="TG_GROUP"
          class="p-3 rounded-2xl bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-800/40 cursor-pointer transition-all duration-300 hover:scale-110 shadow-sm hover:shadow-md group"
          @click="BrowserOpenURL(TG_GROUP)"
          title="Telegram Group"
        >
          <Icon icon="telegram" class="text-2xl text-blue-500 group-hover:text-blue-600 transition-colors" />
        </div>

         <div
          v-if="TG_CHANNEL"
          class="p-3 rounded-2xl bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-800/40 cursor-pointer transition-all duration-300 hover:scale-110 shadow-sm hover:shadow-md group"
          @click="BrowserOpenURL(TG_CHANNEL)"
          title="Telegram Channel"
        >
          <Icon icon="telegram" class="text-2xl text-blue-400 group-hover:text-blue-500 transition-colors" />
        </div>
      </div>
    </div>
    
    <div class="absolute bottom-6 text-xs text-gray-400/60 font-medium tracking-wider">
      DESIGNED FOR PERFORMANCE
    </div>
  </div>
</template>
