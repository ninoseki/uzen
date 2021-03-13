<template>
  <div class="box">
    <nav class="navbar">
      <div class="navbar-brand">
        <H2>
          {{ rule.name }}
        </H2>
      </div>
      <div class="navbar-menu">
        <div class="navbar-end">
          <router-link
            class="button"
            :to="{
              name: 'EditRule',
              params: { id: rule.id },
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
            <Table class="table">
              <tbody>
                <tr>
                  <th>ID</th>
                  <td>{{ rule.id }}</td>
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
            </Table>
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
          <Counter :ruleId="rule.id" />
        </H3>
        <SnapshotTable v-if="hasSnapshots" v-bind:snapshots="rule.snapshots" />
        <p v-else>N/A</p>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import {
  computed,
  defineComponent,
  onMounted,
  PropType,
} from "@vue/composition-api";
import { useTitle } from "@vueuse/core";

import Counter from "@/components/match/Counter.vue";
import SnapshotTable from "@/components/snapshot/TableWithScreenshot.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import { Rule } from "@/types";
import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "Rule",
  components: {
    Counter,
    H2,
    H3,
    SnapshotTable,
  },
  props: {
    rule: {
      type: Object as PropType<Rule>,
      required: true,
    },
  },
  setup(props, context) {
    const updateTitle = (ruleName: string): void => {
      useTitle(`${ruleName} - Uzen`);
    };

    const hasSnapshots = computed(() => {
      return (props.rule.snapshots || []).length > 0;
    });

    onMounted(async () => {
      updateTitle(props.rule.name);

      highlightCodeBlocks(context);
    });

    return { hasSnapshots };
  },
});
</script>
