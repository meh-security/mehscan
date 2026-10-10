<script>export const moduleValue = 'module scope';</script>
<script setup>const moduleValue = window.location.hash; eval(moduleValue);</script>
<template><p v-html="moduleValue"></p></template>
