<script setup lang="ts">
defineProps<{ body: string }>();
</script>
<template><div v-html="body" /></template>
