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
            <th>Namespace</th>
            <td>{{ match.namespace || "N/A" }}</td>
          </tr>
          <tr>
            <th>Rule</th>
            <td>{{ match.rule }}</td>
          </tr>
          <tr>
            <th>Tags</th>
            <td>{{ (match.tags || []).join(",") }}</td>
          </tr>
          <tr>
            <th>Strings</th>
            <td>
              <div v-for="string in match.strings" v-bind:key="string.offset">
                <p><strong>Offset: </strong>{{ string.offset }}</p>
                <p>
                  <strong>String identifier: </strong
                  >{{ string.string_identifier }}
                </p>
                <p><strong>String data: </strong>{{ string.string_data }}</p>
                <br />
              </div>
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
