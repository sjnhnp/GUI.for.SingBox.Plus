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
  <div class="flex flex-col items-center pt-36">
    <img :src="logo" class="w-128" draggable="false" />
    <div class="py-8 font-bold text-24">{{ APP_TITLE }}</div>
    <div class="flex flex-col items-center pb-8 my-4">
      <template v-if="appStore.restartable">
        <Button
          icon="restartApp"
          size="small"
          type="primary"
          @click="handleRestartApp"
        >
          {{ t('about.restart') }}
        </Button>
      </template>
      <template v-else>
        <div class="font-bold text-20 mb-8" style="color: #29b280">
          {{ APP_VERSION }}
        </div>
      </template>
    </div>
    <div
      v-if="appStore.updatable"
      class="mb-8"
    >
      <Button
        :loading="appStore.downloading"
        size="small"
        @click="appStore.downloadApp"
      >
        {{ t('about.new') }}: {{ appStore.remoteVersion }}
      </Button>
    </div>
    <div
      class="text-16 underline flex items-center cursor-pointer mt-12"
      @click="BrowserOpenURL(PROJECT_URL)"
    >
      <Icon icon="github" class="mr-4" />GitHub
    </div>
  </div>
</template>
