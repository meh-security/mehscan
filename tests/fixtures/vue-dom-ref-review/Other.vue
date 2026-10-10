<script setup>
import { ref } from 'another-library';
const output = ref(null);
function write(html) { output.value.innerHTML = html; }
</script>
<template><div ref="output"/></template>
