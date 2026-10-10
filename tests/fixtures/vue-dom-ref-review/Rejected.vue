<script setup>
import { ref } from 'vue';
const repeated = ref(null), looped = ref(null), custom = ref(null), dynamic = ref(null);
function write(html) {
 repeated.value.innerHTML = html;
 looped.value.innerHTML = html;
 custom.value.innerHTML = html;
 dynamic.value.innerHTML = html;
}
</script>
<template>
 <div ref="repeated"/><Widget ref="repeated"/>
 <ul><li v-for="item in items" ref="looped"/></ul>
 <custom-widget ref="custom"/>
 <div :is="which" ref="dynamic"/>
</template>
