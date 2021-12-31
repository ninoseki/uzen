<template>
  <div>
    <div class="box">
      <InputForm
        :name="name"
        :target="target"
        :source="source"
        :allowedNetworkAddresses="allowedNetworkAddresses"
        :disallowedNetworkAddresses="disallowedNetworkAddresses"
        :allowedResourceHashes="allowedResourceHashes"
        :disallowedResourceHashes="disallowedResourceHashes"
        ref="form"
      />

      <div class="has-text-centered mt-5">
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
import { useRouter } from "vue-router";

import InputForm from "@/components/rule/InputForm.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { TargetTypes } from "@/types";
import { generateCreateRuleTask } from "@/api-helper";

export default defineComponent({
  name: "RuleRegister",
  components: {
    Error,
    InputForm,
    Loading,
  },
  setup() {
    const router = useRouter();

    const form = ref<InstanceType<typeof InputForm>>();

    const name = ref("");
    const target = ref<TargetTypes>("html");
    const source = ref("");

    const allowedNetworkAddresses = ref<string | undefined>(undefined);
    const disallowedNetworkAddresses = ref<string | undefined>(undefined);
    const allowedResourceHashes = ref<string | undefined>(undefined);
    const disallowedResourceHashes = ref<string | undefined>(undefined);

    const createRuleTask = generateCreateRuleTask();

    const createRule = async () => {
      const payload = form.value?.getPayload();
      if (payload === undefined) {
        throw "The input form is not mounted!";
      }
      return await createRuleTask.perform(payload);
    };

    const register = async () => {
      const rule = await createRule();
      router.push({ path: `/rules/${rule.id}` });
    };

    return {
      allowedNetworkAddresses,
      allowedResourceHashes,
      createRuleTask,
      disallowedNetworkAddresses,
      disallowedResourceHashes,
      form,
      name,
      source,
      target,
      register,
    };
  },
});
</script>
