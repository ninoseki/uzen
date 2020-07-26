<template>
  <div>
    <div class="box">
      <InputForm
        v-bind:name.sync="name"
        v-bind:target.sync="target"
        v-bind:source.sync="source"
      />

      <div class="has-text-centered">
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="keyboard"
          @click="register"
          >Register</b-button
        >
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import InputForm from "@/components/rules/InputForm.vue";
import { ErrorData, Rule, TargetTypes } from "@/types";

@Component({ components: { InputForm } })
export default class Register extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {
  private name = "";
  private target: TargetTypes = "body";
  private source = "";

  async register() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el.firstElementChild,
    });

    try {
      const response = await axios.post<Rule>("/api/rules/", {
        name: this.name === "" ? undefined : this.name,
        target: this.target,
        source: this.source === "" ? undefined : this.source,
      });
      const rule = response.data;

      loadingComponent.close();

      // redirect to the details page
      this.$router.push({ path: `/rules/${rule.id}` });
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }
}
</script>
