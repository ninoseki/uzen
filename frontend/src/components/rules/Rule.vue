<template>
  <div class="box">
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
        </h2>
        <Table v-if="hasSnapshots()" v-bind:snapshots="rule.snapshots" />
        <p v-else>N/A</p>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Rule, ErrorData } from "@/types";

import Table from "@/components/snapshots/TableWithScreenshot.vue";

import { HighlightMixin } from "@/components/mixins";

@Component({
  components: {
    Table,
  },
})
export default class RuleComponent extends Mixins<HighlightMixin>(
  HighlightMixin
) {
  @Prop() private rule!: Rule;

  mounted() {
    this.highlightCodeBlocks();
  }

  hasSnapshots(): boolean {
    return this.rule.snapshots.length > 0;
  }
}
</script>
