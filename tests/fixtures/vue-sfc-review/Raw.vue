<template>
  <article v-html="html"></article>
</template>
<script setup lang="ts">
const html = new URLSearchParams(window.location.search).get('html') || '';
</script>
