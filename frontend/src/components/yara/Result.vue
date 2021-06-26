<template>
  <div>
    <div
      class="table-container"
      v-for="match in yaraResult.matches"
      :key="match.rule"
    >
      <table class="table is-fullwidth is-completely-borderless">
        <tbody>
          <tr>
            <th>Target</th>
            <td>{{ yaraResult.target }}</td>
          </tr>
          <tr>
            <th>Result</th>
            <td>
              <pre><code class="json">{{ match }}</code></pre>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, PropType } from "@vue/composition-api";

import { YaraResult } from "@/types";
import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "YaraResult",
  props: {
    yaraResult: {
      type: Object as PropType<YaraResult>,
      required: true,
    },
  },
  setup(_, context) {
    onMounted(() => {
      highlightCodeBlocks(context);
    });
  },
});
</script>
