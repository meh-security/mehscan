<script setup lang="ts">
import { render } from './helper';
const props = defineProps<{ html: string }>();
const output = render(props.html);
</script>
<template><section v-html="output" /></template>
