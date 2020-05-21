<template>
  <Import />
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import Import from "@/components/Import.vue";

@Component({
  components: {
    Import,
  },
})
export default class ImportView extends Vue {}
</script>
