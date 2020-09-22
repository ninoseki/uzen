<template>
  <div>
    <p>{{ createdAtInLocalFormat }}</p>
    <p>({{ humanreadableTimeDifference }} ago)</p>
  </div>
</template>

<script lang="ts">
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import timezone from "dayjs/plugin/timezone";
import utc from "dayjs/plugin/utc";
import { Component, Prop, Vue } from "vue-property-decorator";

dayjs.extend(relativeTime);
dayjs.extend(timezone);
dayjs.extend(utc);

@Component
export default class DatetimeWithDiff extends Vue {
  @Prop() private datetime!: string | undefined;

  get createdAtInLocalFormat(): string {
    if (this.datetime === undefined) {
      return "N/A";
    }
    return dayjs(this.datetime).local().format();
  }

  get humanreadableTimeDifference(): string {
    if (this.datetime === undefined) {
      return "N/A";
    }
    return dayjs(this.datetime).local().fromNow();
  }
}
</script>
