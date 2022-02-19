<template>
  <div class="box">
    <nav class="navbar">
      <div class="navbar-brand">
        <H2>Hash: {{ file.id }}</H2>
      </div>
    </nav>

    <table class="table is-completely-borderless is-fullwidth">
      <tr v-if="url">
        <th>URL</th>
        <td>{{ url }}</td>
      </tr>
      <tr>
        <th>First seen</th>
        <td>{{ file.createdAt }}</td>
      </tr>
    </table>

    <HighlightedCode
      :data="file.content"
      v-if="file.content !== ''"
    ></HighlightedCode>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import H2 from "@/components/ui/H2.vue";
import HighlightedCode from "@/components/ui/HighlightedCode.vue";
import NA from "@/components/ui/NA.vue";
import { File } from "@/types";

export default defineComponent({
  name: "FileItem",
  props: {
    file: {
      type: Object as PropType<File>,
      required: true,
    },
    url: {
      type: String,
      required: false,
    },
  },
  components: {
    NA,
    HighlightedCode,
    H2,
  },
});
</script>
