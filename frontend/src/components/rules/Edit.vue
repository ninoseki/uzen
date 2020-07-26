<template>
  <div>
    <div class="box">
      <InputForm
        v-if="hasRule()"
        v-bind:name.sync="rule.name"
        v-bind:target.sync="rule.target"
        v-bind:source.sync="rule.source"
      />

      <div class="has-text-centered">
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="keyboard"
          @click="edit"
          >Edit</b-button
        >
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import InputForm from "@/components/rules/InputForm.vue";
import { ErrorData, Rule } from "@/types";

@Component({ components: { InputForm } })
export default class Edit extends Mixins<ErrorDialogMixin>(ErrorDialogMixin) {
  @Prop() private id!: string;

  private rule: Rule | undefined = undefined;

  async load() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el.firstElementChild,
    });

    try {
      const response = await axios.get<Rule>(`/api/rules/${this.id}`);
      this.rule = response.data;

      loadingComponent.close();

      this.$forceUpdate();
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  async edit() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el.firstElementChild,
    });

    try {
      const response = await axios.put<Rule>(`/api/rules/${this.rule?.id}`, {
        name: this.rule?.name === "" ? undefined : this.rule?.name,
        target: this.rule?.target,
        source: this.rule?.source === "" ? undefined : this.rule?.source,
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

  hasRule(): boolean {
    return this.rule !== undefined;
  }

  async mounted() {
    await this.load();
  }
}
</script>
