<template>
  <div>
    <pre>{{ script.file.content }}</pre>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { Script } from "@/types";

@Component
export default class ScriptComponent extends Vue {
  @Prop() private script!: Script;
}
</script>

<style scoped>
pre {
  word-break: normal;
}
</style>
