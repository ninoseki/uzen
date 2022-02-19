<template>
  <div>
    <article class="message is-warning">
      <div class="message-body">
        Some operations are not allowed without your API key.
      </div>
    </article>

    <div class="box">
      <div class="field">
        <label class="label">Your API key</label>
        <div class="control">
          <input
            class="input"
            type="text"
            v-model="apiKey"
            @input="updateApiKey"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";

import { updateClient } from "@/api";
import { useGlobalState } from "@/store";

export default defineComponent({
  name: "ConfigurationItem",
  setup() {
    const state = useGlobalState();

    const apiKey = ref(state.value.apiKey);

    const updateApiKey = () => {
      state.value.apiKey = apiKey.value;
      updateClient();
    };

    return { apiKey, updateApiKey };
  },
});
</script>
