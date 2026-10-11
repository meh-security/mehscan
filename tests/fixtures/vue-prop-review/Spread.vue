<script setup lang="ts">
import Display from './Rich.vue';
const options = { html: location.search };
</script>
<template><Display v-bind="options" /></template>
