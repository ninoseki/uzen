<template>
  <div>
    <Search />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import Search from "@/components/matches/Search.vue";

@Component({
  components: {
    Search,
  },
})
export default class Matches extends Vue {}
</script>
