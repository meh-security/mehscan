<script setup lang="ts">
interface Props { member: { desc: string }; modelValue?: string }
const props = withDefaults(defineProps<Props>(), { modelValue: '' });
</script>
<template><bdi v-html="member.desc" /></template>
