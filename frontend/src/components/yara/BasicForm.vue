<template>
  <div>
    <b-field label="YARA rule">
      <b-input
        class="is-expanded"
        type="textarea"
        rows="10"
        placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
        v-model="_source"
      ></b-input>
    </b-field>

    <b-field label="Target">
      <b-select placeholder="Target for a YARA rule" v-model="_target">
        <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>
      </b-select>
    </b-field>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import { TargetTypes } from "@/types";

@Component
export default class BasicForm extends Vue {
  private source = "";
  private target: TargetTypes = "body";
  private targets: TargetTypes[] = ["body", "whois", "certificate", "script"];

  get _source() {
    return this.source;
  }

  set _source(value) {
    this.$emit("update:source", value);
  }

  get _target() {
    return this.target;
  }

  set _target(value) {
    this.$emit("update:target", value);
  }
}
</script>
