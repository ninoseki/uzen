<template>
  <div>
    <div class="box">
      <InputForm
        :name="name"
        :target="target"
        :source="source"
        @update-name="updateName"
        @update-source="updateSource"
        @update-target="updateTarget"
      />

      <div class="has-text-centered">
        <button class="button is-light" @click="register">
          <span class="icon">
            <i class="fas fa-keyboard"></i>
          </span>
          <span>Create</span>
        </button>
      </div>
    </div>

    <Loading v-if="createRuleTask.isRunning"></Loading>
    <Error
      :error="createRuleTask.last?.error.response.data"
      v-else-if="createRuleTask.isError"
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
import { Rule, TargetTypes } from "@/types";

export default defineComponent({
  name: "RuleRegister",
  components: {
    Error,
    InputForm,
    Loading,
  },
  setup() {
    const router = useRouter();

    const name = ref("");
    const target = ref<TargetTypes>("html");
    const source = ref("");

    const createRuleTask = useAsyncTask<Rule, []>(async () => {
      const payload = {
        name: name.value,
        target: target.value,
        source: source.value,
      };

      return await API.createRule(payload);
    });

    const register = async () => {
      const rule = await createRuleTask.perform();
      router.push({ path: `/rules/${rule.id}` });
    };

    const updateName = (newName: string) => {
      name.value = newName;
    };

    const updateSource = (newSource: string) => {
      source.value = newSource;
    };

    const updateTarget = (newTarget: TargetTypes) => {
      target.value = newTarget;
    };

    return {
      createRuleTask,
      name,
      source,
      target,
      register,
      updateName,
      updateSource,
      updateTarget,
    };
  },
});
</script>
