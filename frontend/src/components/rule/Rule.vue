<template>
  <div ref="root" class="box">
    <nav class="navbar">
      <div class="navbar-brand">
        <H2>
          {{ rule.name }}
        </H2>
      </div>
      <div class="navbar-menu">
        <div class="navbar-end">
          <div class="navbar-item">
            <router-link
              class="button is-light"
              :to="{
                name: 'EditRule',
                params: { id: rule.id },
              }"
              >Edit
            </router-link>
          </div>
          <div class="navbar-item">
            <button class="button is-danger" @click="deleteRule">
              <span class="icon">
                <i class="fas fa-trash"></i>
              </span>
              <span>Delete</span>
            </button>
          </div>
        </div>
      </div>
    </nav>

    <div class="column">
      <div class="table-container">
        <table class="table is-completely-borderless">
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
              <th>Allowed network addresses</th>
              <td>
                <ValueTags :value="rule.allowedNetworkAddresses"></ValueTags>
              </td>
            </tr>
            <tr>
              <th>Disallowed network addresses</th>
              <td>
                <ValueTags :value="rule.disallowedNetworkAddresses"></ValueTags>
              </td>
            </tr>
            <tr>
              <th>Allowed resource hashes</th>
              <td>
                <ValueTags :value="rule.allowedResourceHashes"></ValueTags>
              </td>
            </tr>
            <tr>
              <th>Disallowed resource hashes</th>
              <td>
                <ValueTags :value="rule.disallowedResourceHashes"></ValueTags>
              </td>
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
        <H3>Source</H3>
        <pre><code class="yara">{{ rule.source || "N/A" }}</code></pre>
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
import { useTitle } from "@vueuse/core";
import { computed, defineComponent, onMounted, PropType, ref } from "vue";
import { useRouter } from "vue-router";

import Counter from "@/components/match/Counter.vue";
import ValueTags from "@/components/rule/ValueTags.vue";
import SnapshotTable from "@/components/snapshot/TableWithScreenshot.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import { Rule } from "@/types";
import { highlightCodeBlocks } from "@/utils/highlight";
import { generateDeleteRuleTask } from "@/api-helper";

export default defineComponent({
  name: "Rule",
  components: {
    Counter,
    H2,
    H3,
    SnapshotTable,
    ValueTags,
  },
  props: {
    rule: {
      type: Object as PropType<Rule>,
      required: true,
    },
  },
  setup(props) {
    const router = useRouter();

    const root = ref<HTMLElement | null>(null);

    const updateTitle = (ruleName: string): void => {
      useTitle(`${ruleName} - Uzen`);
    };

    const hasSnapshots = computed(() => {
      return (props.rule.snapshots || []).length > 0;
    });

    const deleteRuleTask = generateDeleteRuleTask();

    const deleteRule = async () => {
      const decision = confirm("Are you sure you want to delete this rule?");
      if (decision) {
        await deleteRuleTask.perform(props.rule.id);
        router.push({ path: "/" });
      }
    };

    onMounted(async () => {
      updateTitle(props.rule.name);

      if (root.value !== null) {
        highlightCodeBlocks(root.value);
      }
    });

    return { hasSnapshots, root, deleteRule };
  },
});
</script>
