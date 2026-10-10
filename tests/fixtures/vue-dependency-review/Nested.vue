<script setup lang="ts">
import { computed } from 'vue';
const props = defineProps<{ html: string }>();
const html = computed(() => {
  const piece = props.html;
  return `<section>${piece}</section>`;
});
</script>
<template><div v-html="html" /></template>
