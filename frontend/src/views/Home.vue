<template>
  <div>
    <SnapshotForm />
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";

import SnapshotForm from "@/components/snapshots/Form.vue";

@Component({
  components: {
    SnapshotForm,
  },
})
export default class Home extends Vue {}
</script>
