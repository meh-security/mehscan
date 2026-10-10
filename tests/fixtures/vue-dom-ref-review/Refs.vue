<script setup lang="ts">
import { ref as domRef, shallowRef, useTemplateRef } from 'vue';
const body = domRef<HTMLElement | null>(null);
const panel = shallowRef(null);
const keyed = useTemplateRef('my-output');
const widget = domRef(null);
function write(html: string) {
  body.value.innerHTML = html;
  body.value.insertAdjacentHTML('beforeend', html);
  panel.value.outerHTML = html;
  keyed.value.setHTMLUnsafe(html);
  widget.value.innerHTML = html;
  body.value.innerHTML = '<p>Fixed</p>';
}
</script>
<template><div ref="body"/><section ref="panel"/><div ref="my-output"/><Widget ref="widget"/></template>
