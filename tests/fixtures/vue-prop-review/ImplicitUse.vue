<script setup lang="ts">
import Card from './Implicit.vue';
const members = [{ desc: location.search }];
</script>
<template><div v-for="member in members"><Card :member /></div></template>
