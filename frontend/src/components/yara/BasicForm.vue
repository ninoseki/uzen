<template>
  <div>
    <b-field label="YARA rule">
      <b-input
        class="is-expanded"
        type="textarea"
        rows="10"
        placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
        v-model="source"
      ></b-input>
    </b-field>

    <b-field label="Target">
      <b-select placeholder="Target for a YARA rule" v-model="target">
        <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>
      </b-select>
    </b-field>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, watch } from "@vue/composition-api";

import { TargetTypes } from "@/types";

export default defineComponent({
  name: "YaraBasicForom",
  setup(_, context) {
    const source = ref("");
    const target = ref<TargetTypes>("body");
    const targets: TargetTypes[] = ["body", "whois", "certificate", "script"];

    watch(
      [source, target],
      // eslint-disable-next-line no-unused-vars
      (_first, _second) => {
        context.emit("update:source", source.value);
        context.emit("update:target", target.value);
      }
    );

    return { source, target, targets };
  },
});
</script>
