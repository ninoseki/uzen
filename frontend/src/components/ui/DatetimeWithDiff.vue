<template>
  <div>
    <p>{{ createdAtInLocalFormat }}</p>
    <p>({{ humanreadableTimeDifference }})</p>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent } from "@vue/composition-api";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import timezone from "dayjs/plugin/timezone";
import utc from "dayjs/plugin/utc";

dayjs.extend(relativeTime);
dayjs.extend(timezone);
dayjs.extend(utc);

export default defineComponent({
  name: "DatetimeWithDiff",
  props: {
    datetime: {
      type: String,
      required: false,
    },
  },
  setup(props) {
    const createdAtInLocalFormat = computed((): string => {
      if (props.datetime === undefined) {
        return "N/A";
      }
      return dayjs(props.datetime).local().format();
    });

    const humanreadableTimeDifference = computed((): string => {
      if (props.datetime === undefined) {
        return "N/A";
      }
      return dayjs(props.datetime).local().fromNow();
    });

    return { createdAtInLocalFormat, humanreadableTimeDifference };
  },
});
</script>
