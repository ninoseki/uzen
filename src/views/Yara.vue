<template>
  <div>
    <YaraForm />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import YaraForm from "@/components/YaraForm.vue";

@Component({
  components: {
    YaraForm
  }
})
export default class Yara extends Vue {}
</script>
