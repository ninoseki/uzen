<template>
  <div>
    <div class="table-container">
      <table class="table is-expanded">
        <tbody>
          <tr>
            <th>Target</th>
            <td>{{ yaraResult.target }}</td>
          </tr>
          <tr>
            <th>matches</th>
            <td>
              <pre>{{ stringfyMatches() }}</pre>
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

  stringfyMatches(): string {
    return JSON.stringify(this.yaraResult.matches, null, 2);
  }
}
</script>
