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
                  <td>{{ rule.created_at || "N/A" }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">Source</h2>
          <pre>{{ rule.source || "N/A" }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Rule, ErrorData } from "@/types";

@Component
export default class RuleComponent extends Vue {
  @Prop() private rule!: Rule;
}
</script>
