<template>
  <div>
    <Register />
    <br />
    <Search />
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Register from "@/components/rules/Register.vue";
import Search from "@/components/rules/Search.vue";

export default defineComponent({
  name: "RulesView",
  components: {
    Register,
    Search,
  },
});
</script>
