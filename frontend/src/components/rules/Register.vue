<template>
  <div>
    <Loading v-if="createRuleTask.isRunning"></Loading>
    <Error
      :error="createRuleTask.last.error.response.data"
      v-else-if="createRuleTask.isError && createRuleTask.last !== undefined"
    ></Error>

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
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="keyboard"
          @click="register"
          >Register</b-button
        >
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import InputForm from "@/components/rules/InputForm.vue";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
import { Rule, TargetTypes } from "@/types";

export default defineComponent({
  name: "RuleRegister",
  components: {
    Error,
    InputForm,
    Loading,
  },
  setup(_, context) {
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
      context.root.$router.push({ path: `/rules/${rule.id}` });
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
      name,
      target,
      source,
      register,
      createRuleTask,
      updateName,
      updateSource,
      updateTarget,
    };
  },
});
</script>
