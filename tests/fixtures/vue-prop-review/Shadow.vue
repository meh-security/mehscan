<script setup lang="ts">
import { computed } from 'vue';
const props = defineProps<{ html: string }>();
const markup = computed((props: { html: string }) => props.html);
</script>
<template><article v-html="markup" /></template>
