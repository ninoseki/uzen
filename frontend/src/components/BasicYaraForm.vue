<template>
  <div>
    <b-field label="YARA rule">
      <b-input
        class="is-expanded"
        type="textarea"
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
import { Component, Prop, Vue } from "vue-property-decorator";

import { TargetTypes } from "@/types";

@Component
export default class BasicYaraForm extends Vue {
  private source: string = "";
  private target: TargetTypes = "body";
  private targets: TargetTypes[] = ["body", "whois", "certificate"];

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
