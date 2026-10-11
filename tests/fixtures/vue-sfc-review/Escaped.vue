<script setup>
const input = new URLSearchParams(window.location.search).get('html') || '';
const escaped = input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
</script>
<template><article v-html="escaped"></article></template>
