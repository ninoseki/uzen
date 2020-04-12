<template>
  <div>
    <div class="box">
      <b-field label="Name">
        <b-input placeholder="Name of a YARA rule" v-model="name"></b-input>
      </b-field>

      <b-field label="Target">
        <b-select placeholder="Target for a YARA rule" v-model="target">
          <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>
        </b-select>
      </b-field>

      <b-field label="Source of a YARA rule">
        <b-input
          class="is-expanded"
          type="textarea"
          placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
          v-model="source"
        ></b-input>
      </b-field>

      <div class="has-text-centered">
        <b-button type="is-light" @click="register">Register</b-button>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Rule, TargetTypes } from "@/types";

@Component
export default class Register extends Vue {
  private name = "";
  private target: TargetTypes = "body";
  private targets: TargetTypes[] = ["body", "whois", "certificate", "script"];
  private source = "";

  async register() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element,
    });

    try {
      const response = await axios.post<Rule>("/api/rules/", {
        name: this.name,
        target: this.target,
        source: this.source,
      });
      const rule = response.data;

      loadingComponent.close();

      // redirect to the details page
      this.$router.push({ path: `/rules/${rule.id}` });
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      if (typeof data.detail === "string") {
        alert(data.detail);
      } else {
        alert(data.detail[0].msg);
      }
    }
  }
}
</script>
