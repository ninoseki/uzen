<template>
  <div>
    <b-message type="is-warning" has-icon>
      Some operations are not allowed without your API key.
    </b-message>

    <div class="box">
      <b-field label="Your API key">
        <b-input v-model="apiKey" @input="updateApiKey"></b-input>
      </b-field>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";

import { updateClient } from "@/api";
import { useGlobalState } from "@/store";

export default defineComponent({
  name: "Configuration",
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
