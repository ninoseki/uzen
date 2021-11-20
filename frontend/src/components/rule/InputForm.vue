<template>
  <div id="form">
    <div class="field">
      <label class="label">Name</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="Name of a YARA rule"
          v-model="name_"
        />
      </div>
    </div>

    <div class="field">
      <label class="label">Target</label>
      <div class="control">
        <div class="select">
          <select placeholder="Target for a YARA rule" v-model="target_">
            <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>

            <option>Select dropdown</option>
            <option>With options</option>
          </select>
        </div>
      </div>
    </div>

    <div class="field">
      <label class="label">Source of a YARA rule</label>
      <div class="control">
        <textarea
          class="textarea is-expanded"
          type="textarea"
          rows="10"
          placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
          v-model="source_"
        />
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, watchEffect } from "vue";

import { TargetTypes } from "@/types";

export default defineComponent({
  name: "RuleInputForm",
  props: {
    name: {
      type: String,
      rquired: true,
    },
    target: {
      type: String,
      rquired: true,
    },
    source: {
      type: String,
      rquired: true,
    },
  },
  setup(props, context) {
    const targets: TargetTypes[] = ["html", "whois", "certificate", "script"];
    const name_ = ref(props.name);
    const target_ = ref(props.target);
    const source_ = ref(props.source);

    watchEffect(() => {
      context.emit("update-name", name_.value);
      context.emit("update-source", source_.value);
      context.emit("update-target", target_.value);
    });

    return { targets, name_, source_, target_ };
  },
});
</script>
