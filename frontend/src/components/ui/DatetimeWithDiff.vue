<template>
  <div>
    <p>{{ createdAtInLocalFormat() }}</p>
    <p>({{ humanreadableTimeDifference() }} ago)</p>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import moment from "moment/moment";

@Component
export default class DatetimeWithDiff extends Vue {
  @Prop() private datetime!: string | undefined;

  createdAtInLocalFormat(): string {
    if (this.datetime === undefined) {
      return "N/A";
    }
    return moment.parseZone(this.datetime).local().format();
  }

  humanreadableTimeDifference(): string {
    if (this.datetime === undefined) {
      return "N/A";
    }
    return moment.parseZone(this.datetime).local().fromNow(true);
  }
}
</script>
