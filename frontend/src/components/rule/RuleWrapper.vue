<template>
  <div>
    <Loading v-if="getRuleTask.isRunning"></Loading>
    <Error
      :backToRoute="true"
      :error="getRuleTask.last.error.response.data"
      v-else-if="getRuleTask.isError && getRuleTask.last"
    ></Error>
    <RuleComponent
      v-if="getRuleTask.last && getRuleTask.last.value && !getRuleTask.isError"
      :rule="getRuleTask.last.value"
    ></RuleComponent>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import RuleComponent from "@/components/rule/Rule.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Rule } from "@/types";

export default defineComponent({
  name: "RuleWrapper",
  components: {
    Error,
    Loading,
    RuleComponent,
  },
  props: {
    ruleId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const getRuleTask = useAsyncTask<Rule, []>(async () => {
      return await API.getRule(props.ruleId);
    });

    onMounted(async () => {
      await getRuleTask.perform();
    });

    return { getRuleTask };
  },
});
</script>
