<script setup>
const props = defineProps({ html: String });
</script>
<template><div v-html="props.html" /></template>
