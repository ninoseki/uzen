<template>
  <Search />
</template>

<script lang="ts">
import { Vue, Component } from "vue-property-decorator";

import Search from "@/components/snapshots/Search.vue";

@Component({
  components: {
    Search,
  },
})
export default class Snapshots extends Vue {}
</script>
