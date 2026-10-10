<script setup lang="ts">
import DOMPurify from 'dompurify';
import { ref } from 'vue';
const output = ref<HTMLElement | null>(null);
function render(html: string) {
  output.value!.innerHTML = DOMPurify.sanitize(html, { ALLOWED_TAGS: ['span'] });
}
</script>
<template><div ref="output" /></template>
