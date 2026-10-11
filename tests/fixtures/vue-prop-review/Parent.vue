<script setup lang="ts">
import Display from './Rich.vue';
import DOMPurify from 'dompurify';
const input = new URLSearchParams(window.location.search).get('html') || '';
const cleaned = DOMPurify.sanitize(input);
</script>
<template>
  <Display :html="cleaned" />
  <display v-bind:html="input" />
</template>
