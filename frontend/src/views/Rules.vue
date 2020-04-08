<template>
  <div>
    <Register />
    <br />
    <Search />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import Register from "@/components/rules/Register.vue";
import Search from "@/components/rules/Search.vue";

@Component({
  components: {
    Register,
    Search,
  },
})
export default class Rules extends Vue {}
</script>
