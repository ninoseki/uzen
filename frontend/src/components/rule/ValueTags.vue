<template>
  <div v-if="values === undefined">
    <p>N/A</p>
  </div>
  <div class="tags" v-else>
    <span class="tag" v-for="(value, index) in values" :key="index">
      {{ value }}
    </span>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent } from "vue";

export default defineComponent({
  name: "ValueTags",
  props: {
    value: {
      type: String,
    },
  },
  setup(props) {
    const values = computed(() => {
      if (props.value) {
        return props.value.split(",");
      }
      return undefined;
    });

    return {
      values,
    };
  },
});
</script>
