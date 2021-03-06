<template>
  <div>
    <div v-if="getWhoisTask.isRunning">Loading...</div>
    <div
      v-else-if="
        !getWhoisTask.isError && getWhoisTask.last && getWhoisTask.last.value
      "
    >
      <WhoisComponent :whois="getWhoisTask.last.value" />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import NA from "@/components/ui/NA.vue";
import WhoisComponent from "@/components/whois/Whois.vue";
import { Whois } from "@/types/snapshot";

export default defineComponent({
  name: "WhoisWrapper",
  props: {
    whoisId: {
      type: String,
      required: true,
    },
  },
  components: {
    WhoisComponent,
    NA,
  },
  setup(props) {
    const getWhoisTask = useAsyncTask<Whois, []>(async () => {
      return await API.getWhois(props.whoisId);
    });

    getWhoisTask.perform();

    return { getWhoisTask };
  },
});
</script>
