<template>
  <div class="box" v-if="hasRule()">
    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <H3>Info</H3>
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
          <H3>Source</H3>
          <pre><code class="yara">{{ rule.source || "N/A" }}</code></pre>
        </div>
      </div>
      <div class="column">
        <H3>
          Recent related snapshots
          <Counter v-bind:ruleId="rule.id" />
        </H3>
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
import H3 from "@/components/ui/H3.vue";
import { ErrorData, Rule } from "@/types";

@Component({
  components: {
    Counter,
    H3,
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

  updateTitle(): void {
    const name = this.rule?.name || "undefined";
    document.title = `${name} - Uzen`;
  }

  async mounted() {
    await this.load();
    this.updateTitle();
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
