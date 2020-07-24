<template>
  <Domain />
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import Domain from "@/components/domain/Domain.vue";

@Component({
  components: {
    Domain,
  },
})
export default class DomainView extends Vue {
  updateTitle(): void {
    const hostname = this.$route.params.hostname;
    document.title = `${hostname} - Uzen`;
  }

  mounted() {
    this.updateTitle();
  }
}
</script>
