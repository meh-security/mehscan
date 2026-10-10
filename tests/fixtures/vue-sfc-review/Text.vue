<template><p>{{ input }}</p><p v-text="input"></p><img :src="image" /></template>
<script setup lang="ts">
const input = new URLSearchParams(window.location.search).get('text') || '';
const image = '/media/fixed.png';
</script>
