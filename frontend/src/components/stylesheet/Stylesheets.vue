<template>
  <div>
    <b-message type="is-info" has-icon>
      Number of stylesheets: {{ stylesheets.length }}
    </b-message>
    <b-field>
      <b-select
        placeholder="Select a stylesheet"
        expanded
        v-model="selectedId"
        @input="selectStylesheet()"
      >
        <option
          v-for="stylesheet in stylesheets"
          :value="stylesheet.id"
          :key="stylesheet.id"
        >
          {{ stylesheet.url }}
        </option>
      </b-select>
    </b-field>

    <div v-if="stylesheetFileContent !== undefined">
      <div class="column">
        <H3>SHA256 hash</H3>
        <router-link
          :to="{
            name: 'Snapshots',
            query: { stylesheetHash: hash },
          }"
          >{{ hash }}
        </router-link>
      </div>
      <div class="column">
        <H3>Stylesheet</H3>
        <pre><code class="css">{{ stylesheetFileContent }}</code></pre>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType, ref } from "@vue/composition-api";

import H3 from "@/components/ui/H3.vue";
import { Stylesheet } from "@/types";

export default defineComponent({
  name: "Stylesheets",
  props: {
    stylesheets: {
      type: Array as PropType<Stylesheet[]>,
      required: true,
    },
  },
  components: {
    H3,
  },
  setup(props) {
    const selectedId = ref<string | undefined>(undefined);
    const hash = ref<string | undefined>(undefined);
    const stylesheetFileContent = ref<string | undefined>(undefined);

    const selectStylesheet = (): void => {
      const script = props.stylesheets.find(
        (elem) => elem.id === selectedId.value
      );
      if (script) {
        stylesheetFileContent.value = script.file.content;
        hash.value = script.file.id;
      } else {
        stylesheetFileContent.value = undefined;
        hash.value = undefined;
      }
    };

    return { selectedId, selectStylesheet, stylesheetFileContent, hash };
  },
});
</script>
