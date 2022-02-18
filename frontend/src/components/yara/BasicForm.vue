<template>
  <div>
    <div class="field">
      <label class="label">YARA rule</label>
      <div class="control is-expanded">
        <textarea
          class="textarea"
          rows="10"
          placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
          v-model="source"
        />
      </div>
    </div>

    <div class="field">
      <label class="label">Target</label>
      <div class="control">
        <div class="select">
          <select placeholder="Target for a YARA rule" v-model="target">
            <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>
          </select>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, watchEffect } from "vue";

import { TargetTypes } from "@/types";

export default defineComponent({
  name: "YaraBasicForm",
  setup(_, context) {
    const source = ref("");
    const target = ref<TargetTypes>("html");
    const targets: TargetTypes[] = ["html", "whois", "certificate", "script"];

    watchEffect(() => {
      context.emit("update:source", source.value);
      context.emit("update:target", target.value);
    });

    return { source, target, targets };
  },
});
</script>
