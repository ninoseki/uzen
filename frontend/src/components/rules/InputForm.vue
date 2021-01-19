<template>
  <div id="form">
    <b-field label="Name">
      <b-input placeholder="Name of a YARA rule" v-model="name_"></b-input>
    </b-field>

    <b-field label="Target">
      <b-select placeholder="Target for a YARA rule" v-model="target_">
        <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>
      </b-select>
    </b-field>

    <b-field label="Source of a YARA rule">
      <b-input
        class="is-expanded"
        type="textarea"
        rows="10"
        placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
        v-model="source_"
      ></b-input>
    </b-field>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, watch } from "@vue/composition-api";

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

    // eslint-disable-next-line no-unused-vars
    watch([name_, target_, source_], (_first, _second) => {
      context.emit("update-name", name_.value);
      context.emit("update-source", source_.value);
      context.emit("update-target", target_.value);
    });

    return { targets, name_, source_, target_ };
  },
});
</script>

<style scoped>
#form {
  margin-bottom: 0.75rem;
}
</style>
