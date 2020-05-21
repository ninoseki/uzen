<template>
  <SnapshotForm />
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import SnapshotForm from "@/components/snapshots/Form.vue";

@Component({
  components: {
    SnapshotForm,
  },
})
export default class Home extends Vue {}
</script>
