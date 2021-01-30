<template>
  <div>
    <b-message type="is-info" has-icon>
      Number of scripts: {{ scripts.length }}
    </b-message>
    <b-field>
      <b-select
        placeholder="Select a script"
        expanded
        v-model="selectedId"
        @input="selectScript()"
      >
        <option v-for="script in scripts" :value="script.id" :key="script.id">
          {{ script.url }}
        </option>
      </b-select>
    </b-field>

    <div v-if="scriptFileContent !== undefined">
      <div class="column">
        <H3>SHA256 hash</H3>
        <router-link
          :to="{
            name: 'Snapshots',
            query: { scriptHash: hash },
          }"
          >{{ hash }}
        </router-link>
      </div>
      <div class="column">
        <H3>Script</H3>
        <pre><code class="javascript">{{ scriptFileContent }}</code></pre>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType, ref } from "@vue/composition-api";

import H3 from "@/components/ui/H3.vue";
import { Script } from "@/types";

export default defineComponent({
  name: "Scripts",
  props: {
    scripts: {
      type: Array as PropType<Script[]>,
      required: true,
    },
  },
  components: {
    H3,
  },
  setup(props) {
    const selectedId = ref<string | undefined>(undefined);
    const hash = ref<string | undefined>(undefined);
    const scriptFileContent = ref<string | undefined>(undefined);

    const selectScript = (): void => {
      const script = props.scripts.find((elem) => elem.id === selectedId.value);
      if (script) {
        scriptFileContent.value = script.file.content;
        hash.value = script.file.id;
      } else {
        scriptFileContent.value = undefined;
        hash.value = undefined;
      }
    };

    return { selectedId, selectScript, scriptFileContent, hash };
  },
});
</script>
