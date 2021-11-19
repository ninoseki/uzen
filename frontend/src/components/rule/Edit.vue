<template>
  <div>
    <div class="box">
      <InputForm
        v-if="hasRule"
        :name="name"
        :target="target"
        :source="source"
        @update-name="updateName"
        @update-source="updateSource"
        @update-target="updateTarget"
      ></InputForm>

      <div class="has-text-centered">
        <button class="button is-light" @click="edit">
          <span class="icon">
            <i class="fas fa-keyboard"></i>
          </span>
          <span>Edit</span>
        </button>
      </div>
    </div>

    <Loading v-if="getRuleTask.isRunning || editRuleTask.isRunning"></Loading>
    <Error
      :error="getRuleTask.last.error.response.data"
      v-else-if="getRuleTask.isError && getRuleTask.last"
    ></Error>
    <Error
      :error="editRuleTask.last.error.response.data"
      v-else-if="editRuleTask.isError && editRuleTask.last"
    ></Error>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";
import { useAsyncTask } from "vue-concurrency";
import { useRouter } from "vue-router";

import { API } from "@/api";
import InputForm from "@/components/rule/InputForm.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Rule } from "@/types";

export default defineComponent({
  name: "RuleEdit",
  components: {
    Error,
    InputForm,
    Loading,
  },
  props: {
    ruleId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const router = useRouter();

    const name = ref<string | undefined>(undefined);
    const target = ref<string | undefined>(undefined);
    const source = ref<string | undefined>(undefined);

    const hasRule = ref(false);

    const getRuleTask = useAsyncTask<Rule, []>(async () => {
      return API.getRule(props.ruleId);
    });

    const getRule = async () => {
      const rule = await getRuleTask.perform();
      name.value = rule.name;
      target.value = rule.target;
      source.value = rule.source;

      hasRule.value = true;
    };

    getRule();

    const editRuleTask = useAsyncTask<Rule, []>(async () => {
      const payload = {
        name: name.value === "" ? undefined : name.value,
        target: target.value,
        source: source.value === "" ? undefined : source.value,
      };

      return API.editRule(props.ruleId, payload);
    });

    const edit = async () => {
      await editRuleTask.perform();
      router.push({ path: `/rules/${props.ruleId}` });
    };

    const updateName = (newName: string) => {
      name.value = newName;
    };

    const updateSource = (newSource: string) => {
      source.value = newSource;
    };

    const updateTarget = (newTarget: string) => {
      target.value = newTarget;
    };

    return {
      editRuleTask,
      getRuleTask,
      hasRule,
      name,
      source,
      target,
      edit,
      updateName,
      updateSource,
      updateTarget,
    };
  },
});
</script>
