<template>
  <div>
    <div
      class="table-container"
      v-for="match in yaraResult.matches"
      v-bind:key="match.rule"
    >
      <table class="table is-expanded">
        <tbody>
          <tr>
            <th>Target</th>
            <td>{{ yaraResult.target }}</td>
          </tr>
          <tr>
            <th>Result</th>
            <td>
              <pre><code class="json">{{ match }}</code></pre>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { YaraResult } from "@/types";

@Component
export default class YaraResultView extends Vue {
  @Prop() private yaraResult!: YaraResult;
}
</script>
