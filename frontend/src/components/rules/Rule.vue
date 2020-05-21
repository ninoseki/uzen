<template>
  <div class="box" v-if="hasRule()">
    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">Info</h2>
          <div class="table-container">
            <table class="table">
              <tbody>
                <tr>
                  <th>ID</th>
                  <td>{{ rule.id || "N/A" }}</td>
                </tr>
                <tr>
                  <th>Name</th>
                  <td>{{ rule.name }}</td>
                </tr>
                <tr>
                  <th>Target</th>
                  <td>{{ rule.target }}</td>
                </tr>
                <tr>
                  <th>Created at</th>
                  <td>{{ rule.createdAt || "N/A" }}</td>
                </tr>
                <tr>
                  <th>Updated at</th>
                  <td>{{ rule.updatedAt || "N/A" }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">Source</h2>
          <pre><code class="yara">{{ rule.source || "N/A" }}</code></pre>
        </div>
      </div>
      <div class="column">
        <h2 class="is-size-5 has-text-weight-bold middle">
          Recent related snapshots
          <Counter v-bind:ruleId="rule.id" />
        </h2>
        <Table v-if="hasSnapshots()" v-bind:snapshots="rule.snapshots" />
        <p v-else>N/A</p>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import Counter from "@/components/matches/Counter.vue";
import {
  ErrorDialogMixin,
  HighlightComponentMixin,
  HighlightMixin,
} from "@/components/mixins";
import Table from "@/components/snapshots/TableWithScreenshot.vue";
import { ErrorData, Rule } from "@/types";

@Component({
  components: {
    Counter,
    Table,
  },
})
export default class RuleComponent extends Mixins<HighlightComponentMixin>(
  HighlightMixin,
  ErrorDialogMixin
) {
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

  async mounted() {
    await this.load();
    this.highlightCodeBlocks();
  }

  hasRule(): boolean {
    return this.rule !== undefined;
  }

  hasSnapshots(): boolean {
    return (this.rule?.snapshots || []).length > 0;
  }
}
</script>
