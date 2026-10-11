<script setup lang="ts">
import { ref } from 'vue';
interface Props { items: Record<string, string> }
const props = defineProps<Props>();
const target = ref<HTMLElement | null>(null);
function update() {
  let output = target.value!.innerText;
  const replacementString = `<mark data-preview="${props.items.key}">text</mark>`;
  output = output.replace('text', replacementString);
  target.value!.innerHTML = output;
}
</script><template><div ref="target" /></template>
