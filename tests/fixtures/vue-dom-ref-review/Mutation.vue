<script setup>
import { ref } from 'vue';
const output = ref(null);
output.value = replacement;
function write(html) { output.value.innerHTML = html; }
</script>
<template><div ref="output"/></template>
