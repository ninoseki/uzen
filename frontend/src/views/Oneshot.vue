<template>
  <Oneshot />
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import Oneshot from "@/components/Oneshot.vue";

@Component({
  components: {
    Oneshot,
  },
})
export default class OneshotView extends Vue {}
</script>
