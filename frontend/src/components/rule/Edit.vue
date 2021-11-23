<template>
  <div>
    <div class="box">
      <InputForm
        v-if="hasRule"
        :name="name"
        :target="target"
        :source="source"
        :allowedNetworkAddresses="allowedNetworkAddresses"
        :disallowedNetworkAddresses="disallowedNetworkAddresses"
        :allowedResourceHashes="allowedResourceHashes"
        :disallowedResourceHashes="disallowedResourceHashes"
        ref="form"
      ></InputForm>

      <div class="has-text-centered mt-5">
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

    const form = ref<InstanceType<typeof InputForm>>();

    const name = ref<string>("");
    const target = ref<string>("");
    const source = ref<string>("");

    const allowedNetworkAddresses = ref<string | undefined>(undefined);
    const disallowedNetworkAddresses = ref<string | undefined>(undefined);
    const allowedResourceHashes = ref<string | undefined>(undefined);
    const disallowedResourceHashes = ref<string | undefined>(undefined);

    const hasRule = ref(false);

    const getRuleTask = useAsyncTask<Rule, []>(async () => {
      return API.getRule(props.ruleId);
    });

    const getRule = async () => {
      const rule = await getRuleTask.perform();
      name.value = rule.name;
      target.value = rule.target;
      source.value = rule.source;

      allowedNetworkAddresses.value = rule.allowedNetworkAddresses;
      disallowedNetworkAddresses.value = rule.disallowedNetworkAddresses;
      allowedResourceHashes.value = rule.allowedResourceHashes;
      disallowedResourceHashes.value = rule.disallowedResourceHashes;

      hasRule.value = true;
    };

    getRule();

    const editRuleTask = useAsyncTask<Rule, []>(async () => {
      const payload = form.value?.getPayload();
      if (payload === undefined) {
        throw "The input form is not mounted!";
      }

      return API.editRule(props.ruleId, payload);
    });

    const edit = async () => {
      await editRuleTask.perform();
      router.push({ path: `/rules/${props.ruleId}` });
    };

    return {
      allowedNetworkAddresses,
      allowedResourceHashes,
      disallowedNetworkAddresses,
      disallowedResourceHashes,
      editRuleTask,
      form,
      getRuleTask,
      hasRule,
      name,
      source,
      target,
      edit,
    };
  },
});
</script>
