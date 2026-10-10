<script setup>
import { ref } from 'vue';
const input = ref(null);
function shadow(input, html) { input.value.innerHTML = html; }
function actual(html) { input.value.innerHTML = html; }
function nested(html) { const input = localFactory(); input.value.innerHTML = html; }
</script>
<template><div ref="input"/></template>
