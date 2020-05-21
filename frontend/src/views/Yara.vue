<template>
  <YaraForm />
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import YaraForm from "@/components/yara/Form.vue";

@Component({
  components: {
    YaraForm,
  },
})
export default class Yara extends Vue {}
</script>
