<template>
  <Form />
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import Form from "@/components/bulk/Form.vue";

@Component({
  components: {
    Form,
  },
})
export default class Bulk extends Vue {}
</script>
