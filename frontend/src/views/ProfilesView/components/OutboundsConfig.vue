<script lang="ts" setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { DraggableOptions } from '@/constant/app'
import { BuiltInOutbound } from '@/constant/kernel'
import { DefaultOutbound } from '@/constant/profile'
import { Outbound } from '@/enums/kernel'
import { useSubscribesStore } from '@/stores'
import { deepClone, message, modal } from '@/utils'

import OutboundForm from './OutboundForm.vue'
import OutboundSort from './OutboundSort.vue'

const model = defineModel<App.Profile['outbounds']>({ required: true })

const isStrategy = (type: string) =>
  [Outbound.Selector, Outbound.Urltest, Outbound.Direct, Outbound.Block].includes(type as any)

const strategyGroups = computed({
  get: () => model.value.filter((v) => isStrategy(v.type)),
  set: (val) => {
    const proxies = model.value.filter((v) => !isStrategy(v.type))
    model.value = [...val, ...proxies]
  },
})

const proxyNodes = computed(() => model.value.filter((v) => !isStrategy(v.type)))

const { t } = useI18n()
const subscribesStore = useSubscribesStore()

const handleAdd = () => openOutboundModal(DefaultOutbound(), -1)

defineExpose({ handleAdd })

const handleDeleteGroup = (outbound: App.Outbound) => {
  const index = model.value.findIndex((v) => v.id === outbound.id)
  if (index === -1) return
  model.value.splice(index, 1)
}

const handleClearGroup = async (outbound: App.Outbound) => {
  const filtered = outbound.outbounds.filter(({ id, type }) => {
    if (type === 'Built-in') {
      return model.value.some((v) => v.id === id)
    } else if (type === 'Subscription') {
      return subscribesStore.getSubscribeById(id)
    }
    const sub = subscribesStore.getSubscribeById(type)
    return sub && sub.proxies.some((v) => v.id === id)
  })
  outbound.outbounds.splice(0)
  outbound.outbounds.push(...filtered)
}

const openOutboundModal = (outbound: App.Outbound, index: number) => {
  const draft = ref(deepClone(outbound))
  const m = modal({
    title: 'kernel.outbounds.name',
    width: '80',
    height: '80',
    onOk: () => {
      if (index === -1) {
        model.value.unshift(draft.value)
        return
      }

      model.value[index] = draft.value
      const { id, tag } = draft.value
      model.value
        .filter((item) => [Outbound.Selector, Outbound.Urltest].includes(item.type as any))
        .forEach(({ outbounds }) => {
          const reference = outbounds.find((item) => item.id === id)
          reference && (reference.tag = tag)
        })
    },
  })
  m.setContent(OutboundForm, { outbound: draft.value, outbounds: model.value }).open()
}

const handleEditGroup = (outbound: App.Outbound) => {
  const index = model.value.findIndex((v) => v.id === outbound.id)
  if (index === -1) return
  openOutboundModal(model.value[index]!, index)
}

const hasLost = (outbound: App.Outbound) => {
  if ([Outbound.Selector, Outbound.Urltest].includes(outbound.type as any)) {
    return outbound.outbounds.some(({ id, type }) => {
      if (type === 'Built-in') {
        if (BuiltInOutbound.includes(id as Outbound)) {
          return false
        }
        return model.value.every((v) => v.id !== id)
      } else if (type === 'Subscription') {
        const sub = subscribesStore.getSubscribeById(id)
        if (!sub) return true
        return false
      }
      const sub = subscribesStore.getSubscribeById(type)
      if (!sub) return true
      return sub.proxies.every((v) => v.id !== id)
    })
  }
  return false
}

const handleSortGroup = (outbound: App.Outbound) => {
  const index = model.value.findIndex((v) => v.id === outbound.id)
  if (index === -1) return
  const draft = ref(deepClone(model.value[index]!))
  const m = modal({
    title: 'kernel.outbounds.sort',
    maxWidth: '80',
    maxHeight: '80',
    maskClosable: true,
    onOk: () => {
      model.value[index] = draft.value
    },
  })
  m.setContent(OutboundSort, { outbound: draft.value }).open()
}

const clacSubscriptionsCount = (outbound: App.Outbound) => {
  if ([Outbound.Selector, Outbound.Urltest].includes(outbound.type as any)) {
    return outbound.outbounds.filter((v) => v.type === 'Subscription').length
  }
  return 0
}

const clacOutboundsCount = (outbound: App.Outbound) => {
  if ([Outbound.Selector, Outbound.Urltest].includes(outbound.type as any)) {
    return outbound.outbounds.filter((v) => v.type !== 'Subscription').length
  }
  return 0
}

const needToAdd = (outbound: App.Outbound) => {
  if ([Outbound.Selector, Outbound.Urltest].includes(outbound.type as any)) {
    return outbound.outbounds.length === 0
  }
  return false
}

const showLost = () => message.warn('kernel.outbounds.notFound')

const showNeedToAdd = () => message.error('kernel.outbounds.needToAdd')
</script>

<template>
  <Empty v-if="model.length === 0">
    <template #description>
      <Button icon="add" type="primary" size="small" @click="handleAdd">
        {{ t('common.add') }}
      </Button>
    </template>
  </Empty>

  <div v-draggable="[strategyGroups, DraggableOptions]">
    <Card v-for="outbound in strategyGroups" :key="outbound.id" class="mb-2">
      <div class="flex items-center py-2">
        <div class="font-bold flex items-center" style="min-width: 90px">
          <img v-if="outbound.icon" :src="outbound.icon" class="w-18 h-18 mr-4" />
          <span
            v-if="hasLost(outbound)"
            class="cursor-pointer"
            style="color: rgb(200, 193, 11)"
            @click="showLost"
          >
            [ ! ]
          </span>
          <span
            v-if="needToAdd(outbound)"
            class="cursor-pointer"
            style="color: red"
            @click="showNeedToAdd"
          >
            [ ! ]
          </span>
          {{ outbound.tag }}
        </div>
        <Button type="link" size="small" @click="handleSortGroup(outbound)">
          (
          {{ t('kernel.outbounds.refsOutbound') }}:{{ clacOutboundsCount(outbound) }}
          /
          {{ t('kernel.outbounds.refsSubscription') }}:{{ clacSubscriptionsCount(outbound) }}
          )
        </Button>
        <div class="ml-auto">
          <Button v-if="hasLost(outbound)" type="text" @click="handleClearGroup(outbound)">
            {{ t('common.clear') }}
          </Button>
          <Button icon="edit" type="text" size="small" @click="handleEditGroup(outbound)" />
          <Button icon="delete" type="text" size="small" @click="handleDeleteGroup(outbound)" />
        </div>
      </div>
    </Card>
  </div>

  <Divider v-if="proxyNodes.length" class="text-12 opacity-50">
    {{ t('common.details') }} ({{ proxyNodes.length }} {{ t('kernel.outbounds.builtIn') }})
  </Divider>
</template>
