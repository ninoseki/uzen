<template>
  <div>
    <div class="box">
      <article class="message is-info">
        <div class="message-body">Scan snapshots with HTML similarity</div>
      </article>

      <div class="columns">
        <div class="column is-half">
          <div class="field">
            <label class="label">Hash (SHA256)</label>
            <div class="control">
              <input
                class="input"
                type="text"
                placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9"
                v-model="hash"
              />
            </div>
          </div>
        </div>

        <div class="column is-half">
          <div class="field">
            <label class="label">Threshold</label>
            <div class="control">
              <input
                class="input"
                type="number"
                placeholder="Text input"
                step="0.1"
                v-model="threshold"
                min="0.0"
                max="1.0"
              />
            </div>
          </div>
        </div>
      </div>

      <div class="columns">
        <div class="column is-half">
          <div class="field">
            <label class="label">Hostname to exclude</label>
            <div class="control">
              <input
                class="input"
                type="text"
                placeholder="example.com"
                v-model="excludeHostname"
              />
            </div>
          </div>
        </div>
        <div class="column is-half">
          <div class="field">
            <label class="label">IP address to exclude</label>
            <div class="control">
              <input
                class="input"
                type="text"
                placeholder="1.1.1.1"
                v-model="excludeIPAddress"
              />
            </div>
          </div>
        </div>
      </div>

      <hr />

      <SnapshotForm ref="form" />

      <div class="has-text-centered mt-5">
        <button class="button" @click="scan">
          <span class="icon">
            <i class="fas fa-search"></i>
          </span>
          <span>Scan</span>
        </button>
      </div>
    </div>
    <Error
      :error="scanTask.last.error.response.data"
      v-if="scanTask.isError && scanTask.last"
    ></Error>
  </div>
</template>

<script lang="ts">
import { useRouteQuery } from "@vueuse/router";
import { defineComponent, Ref, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import { API } from "@/api";
import SnapshotForm from "@/components/snapshot/SearchForm.vue";
import Error from "@/components/ui/SimpleError.vue";
import { SimilarityScanPayload } from "@/types";
import { generateSimilarityScanTask } from "@/api-helper";

export default defineComponent({
  name: "SimilarityForm",
  components: {
    SnapshotForm,
    Error,
  },
  setup() {
    const router = useRouter();
    const route = useRoute();
    const options = { route, router };

    const hash = useRouteQuery("hash", "", options) as Ref<string>;
    const excludeHostname = useRouteQuery(
      "excludeHostname",
      undefined,
      options
    ) as Ref<string | undefined>;
    const excludeIPAddress = useRouteQuery(
      "excludeIPAddress",
      undefined,
      options
    ) as Ref<string | undefined>;
    const threshold = ref<number>(0.9);

    const form = ref<InstanceType<typeof SnapshotForm>>();

    const scanTask = generateSimilarityScanTask();

    const scan = async () => {
      // get parameters from the child component
      const params = form.value?.filtersParams() || {};

      // get total count of snapshots and set it as a size
      try {
        const totalCount = await API.getTotalSnapshotCount();
        params["size"] = totalCount.count;
      } catch {
        // do nothing;
      }

      // get HTML
      const html = await API.getHTML(hash.value);

      const payload: SimilarityScanPayload = {
        html: html.content || "",
        threshold: threshold.value,
        excludeHostname:
          excludeHostname.value === "" ? undefined : excludeHostname.value,
        excludeIPAddress:
          excludeIPAddress.value === "" ? undefined : excludeIPAddress.value,
      };

      const job = await scanTask.perform(payload, params);

      router.push({ path: `/jobs/similarity/${job.id}` });
    };

    return {
      excludeHostname,
      excludeIPAddress,
      form,
      hash,
      scanTask,
      threshold,
      scan,
    };
  },
});
</script>
