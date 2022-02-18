<template>
  <div>
    <Loading v-if="getWhoisTask.isRunning"></Loading>
    <div v-else-if="!getWhoisTask.isError && getWhoisTask.last?.value">
      <WhoisComponent :whois="getWhoisTask.last.value" />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";

import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import WhoisComponent from "@/components/whois/Whois.vue";
import { generateGetWhoisTask } from "@/api-helper";

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
    Loading,
  },
  setup(props) {
    const getWhoisTask = generateGetWhoisTask();

    onMounted(async () => {
      await getWhoisTask.perform(props.whoisId);
    });

    return { getWhoisTask };
  },
});
</script>
