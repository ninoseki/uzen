<template>
  <div class="row">
    <div v-if="hasResult()">
      <div v-if="isErrorResult()">
        <b-message type="is-danger">
          Failed to take snapshot of {{ url }}
        </b-message>
      </div>
      <div v-else>
        <b-message type="is-success">
          <router-link
            :to="{
              name: 'Snapshot',
              params: {
                id: result.id,
              },
            }"
          >
            {{ result.url | truncate }}
          </router-link>
          <p><strong>Submitted URL:</strong> {{ url }}</p>
          <p><strong>ID:</strong> {{ result.id }}</p>
        </b-message>
      </div>
    </div>
    <div v-else>
      <b-message>Loading {{ url }}...</b-message>
    </div>
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Prop, Vue } from "vue-property-decorator";

import { ErrorData, Snapshot } from "@/types";

@Component
export default class Row extends Vue {
  @Prop() private url!: string;
  @Prop() private index!: number;

  @Prop() private acceptLanguage!: string;
  @Prop() private host!: string;
  @Prop() private ignoreHTTPSErrors!: boolean;
  @Prop() private referer!: string;
  @Prop() private timeout!: number;
  @Prop() private userAgent!: string;

  private result: Snapshot | ErrorData | undefined = undefined;

  sleep(): Promise<void> {
    const timeout = 1000 * this.index;
    return new Promise((resolve) => setTimeout(resolve, timeout));
  }

  mounted() {
    this.submit();
  }

  async submit() {
    await this.sleep();

    try {
      const response = await axios.post<Snapshot>("/api/snapshots/", {
        url: this.url,
        acceptLanguage:
          this.acceptLanguage === "" ? undefined : this.acceptLanguage,
        host: this.host === "" ? undefined : this.host,
        ignoreHttpsErrors: this.ignoreHTTPSErrors,
        referer: this.referer === "" ? undefined : this.referer,
        timeout: this.timeout,
        userAgent: this.userAgent === "" ? undefined : this.userAgent,
      });
      this.result = response.data;
    } catch (error) {
      let data = error.response.data as ErrorData;
      if (typeof data === "string") {
        data = { detail: error };
      }
      this.result = data;
    }
    this.$forceUpdate();
  }

  hasResult(): boolean {
    return this.result !== undefined;
  }

  isErrorResult(): boolean {
    return this.result !== undefined && "detail" in this.result;
  }
}
</script>

<style scoped>
.row {
  margin-top: 10px;
  margin-bottom: 10px;
}
</style>
