<template>
  <div id="form">
    <b-field label="Name">
      <b-input placeholder="Name of a YARA rule" v-model="_name"></b-input>
    </b-field>

    <b-field label="Target">
      <b-select placeholder="Target for a YARA rule" v-model="_target">
        <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>
      </b-select>
    </b-field>

    <b-field label="Source of a YARA rule">
      <b-input
        class="is-expanded"
        type="textarea"
        rows="10"
        placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
        v-model="_source"
      ></b-input>
    </b-field>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { TargetTypes } from "@/types";

@Component
export default class InputForm extends Vue {
  @Prop() private name;
  @Prop() private target;
  @Prop() private source;

  private targets: TargetTypes[] = ["body", "whois", "certificate", "script"];

  get _name() {
    return this.name;
  }

  set _name(value) {
    this.$emit("update:name", value);
  }

  get _target() {
    return this.target;
  }

  set _target(value) {
    this.$emit("update:target", value);
  }

  get _source() {
    return this.source;
  }

  set _source(value) {
    this.$emit("update:source", value);
  }
}
</script>

<style scoped>
#form {
  margin-bottom: 0.75rem;
}
</style>
