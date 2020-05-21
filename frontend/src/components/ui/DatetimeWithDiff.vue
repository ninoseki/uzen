<template>
  <div>
    <p>{{ createdAtInLocalFormat() }}</p>
    <p>({{ humanreadableTimeDifference() }} ago)</p>
  </div>
</template>

<script lang="ts">
import moment from "moment/moment";
import { Component, Prop, Vue } from "vue-property-decorator";

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
