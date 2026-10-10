<script setup lang="ts">
import { ref } from 'vue';
import DOMPurify from 'dompurify';
const output = ref<HTMLElement | null>(null);
function render(html: string) {
  output.value.innerHTML = DOMPurify.sanitize(html, { ALLOWED_TAGS: ['span'] });
}
</script>
<template><div ref="output"/></template>
