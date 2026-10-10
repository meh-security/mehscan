<script setup>
import StaticSink from './StaticSink.vue';
const input = location.search;
const items = [input];
</script>
<template>
  <StaticSink html="input" />
  <StaticSink v-for="input in items" :html="input" />
</template>
