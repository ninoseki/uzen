<template>
  <div>
    <b-message type="is-info">
      Number of scripts: {{ scripts.length }}
    </b-message>
    <b-field>
      <b-select
        placeholder="Select a script"
        expanded
        v-model="selectedID"
        @input="selectScript()"
      >
        <option v-for="script in scripts" :value="script.id" :key="script.id">
          {{ script.url }}
        </option>
      </b-select>
    </b-field>
    <pre
      v-if="scriptFileContent !== undefined"
    ><code class="javascript">{{ scriptFileContent }}</code></pre>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType, ref } from "@vue/composition-api";

import { Script } from "@/types";

export default defineComponent({
  name: "Scripts",
  props: {
    scripts: {
      type: Array as PropType<Script[]>,
      required: true,
    },
  },
  setup(props) {
    const selectedID = ref<string | undefined>(undefined);
    const scriptFileContent = ref<string | undefined>(undefined);

    const selectScript = (): void => {
      const script = props.scripts.find((elem) => elem.id === selectedID.value);
      if (script) {
        scriptFileContent.value = script.file.content;
      } else {
        scriptFileContent.value = undefined;
      }
    };

    return { selectedID, selectScript, scriptFileContent };
  },
});
</script>
