<script setup lang="ts">
import Display from './unrelated/Rich.vue';
const input = location.search;
</script>
<template><Display :html="input" /></template>
