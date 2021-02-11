<template>
  <div>
    <Loading v-if="getRuleTask.isRunning"></Loading>
    <Error
      :error="getRuleTask.last.error.response.data"
      v-else-if="getRuleTask.isError && getRuleTask.last !== undefined"
    ></Error>

    <div
      class="box"
      v-if="getRuleTask.last && getRuleTask.last.value && !getRuleTask.isError"
    >
      <nav class="navbar">
        <div class="navbar-brand">
          <H2>
            {{ getRuleTask.last.value.name }}
          </H2>
        </div>
        <div class="navbar-menu">
          <div class="navbar-end">
            <router-link
              class="button"
              :to="{
                name: 'EditRule',
                params: { id: getRuleTask.last.value.id },
              }"
              >Edit
            </router-link>
          </div>
        </div>
      </nav>

      <div class="column is-full">
        <div class="columns">
          <div class="column is-half">
            <div class="table-container">
              <table class="table">
                <tbody>
                  <tr>
                    <th>ID</th>
                    <td>{{ getRuleTask.last.value.id }}</td>
                  </tr>
                  <tr>
                    <th>Target</th>
                    <td>{{ getRuleTask.last.value.target }}</td>
                  </tr>
                  <tr>
                    <th>Created at</th>
                    <td>{{ getRuleTask.last.value.createdAt || "N/A" }}</td>
                  </tr>
                  <tr>
                    <th>Updated at</th>
                    <td>{{ getRuleTask.last.value.updatedAt || "N/A" }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="column is-half">
            <H3>Source</H3>
            <pre><code class="yara">{{ getRuleTask.last.value.source || "N/A" }}</code></pre>
          </div>
        </div>
        <div class="column">
          <H3>
            Recent related snapshots
            <Counter :ruleId="getRuleTask.last.value.id" />
          </H3>
          <Table
            v-if="hasSnapshots(getRuleTask.last.value)"
            v-bind:snapshots="getRuleTask.last.value.snapshots"
          />
          <p v-else>N/A</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "@vue/composition-api";
import { useTitle } from "@vueuse/core";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Counter from "@/components/match/Counter.vue";
import Table from "@/components/snapshot/TableWithScreenshot.vue";
import Error from "@/components/ui/Error.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import Loading from "@/components/ui/Loading.vue";
import { Rule } from "@/types";
import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "Rule",
  components: {
    Counter,
    Error,
    H2,
    H3,
    Loading,
    Table,
  },
  props: {
    ruleId: {
      type: String,
      required: true,
    },
  },
  setup(props, context) {
    const getRuleTask = useAsyncTask<Rule, []>(async () => {
      return await API.getRule(props.ruleId);
    });

    const updateTitle = (ruleName: string): void => {
      useTitle(`${ruleName} - Uzen`);
    };

    const getRule = async () => {
      const rule = await getRuleTask.perform();
      updateTitle(rule.name);
    };

    const hasSnapshots = (rule: Rule): boolean => {
      return (rule?.snapshots || []).length > 0;
    };

    onMounted(async () => {
      await getRule();
      highlightCodeBlocks(context);
    });

    return { getRuleTask, hasSnapshots };
  },
});
</script>
