<!-- <script>eval(tutorialSnippet)</script> -->
<template><p>{{ message }}</p></template>
<script setup>
const message = new URLSearchParams(window.location.search).get('code') || '';
eval(message);
</script>
<style>p { content: 'eval(cssExample)'; }</style>
