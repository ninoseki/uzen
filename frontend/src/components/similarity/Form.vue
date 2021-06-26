<template>
  <div>
    <div class="box">
      <b-message type="is-info">Scan snapshots with HTML similarity</b-message>

      <div class="columns">
        <div class="column is-half">
          <b-field label="Hash (SHA256)">
            <b-input
              placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9"
              v-model="hash"
            ></b-input>
          </b-field>
        </div>

        <div class="column is-half">
          <b-field label="Threshold">
            <b-numberinput
              type="is-light"
              step="0.1"
              v-model="threshold"
              min="0.0"
              max="1.0"
            ></b-numberinput>
          </b-field>
        </div>
      </div>

      <div class="columns">
        <div class="column is-half">
          <b-field label="Hostname to exclude">
            <b-input
              placeholder="example.com"
              v-model="excludeHostname"
            ></b-input>
          </b-field>
        </div>
        <div class="column is-half">
          <b-field label="IP address to exclude">
            <b-input placeholder="1.1.1.1" v-model="excludeIPAddress"></b-input>
          </b-field>
        </div>
      </div>

      <hr />

      <SnapshotForm ref="form" />

      <div class="has-text-centered mt-5">
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="search"
          @click="scan"
          >Scan</b-button
        >
      </div>
    </div>
    <Error
      :error="scanTask.last.error.response.data"
      v-if="scanTask.isError && scanTask.last !== undefined"
    ></Error>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SnapshotForm from "@/components/snapshot/SearchForm.vue";
import Error from "@/components/ui/Error.vue";
import { Job, SimilarityScanPayload } from "@/types";

export default defineComponent({
  name: "SimilarityForm",
  components: {
    SnapshotForm,
    Error,
  },
  setup(_, context) {
    const hash = ref(
      (context.root.$route.query["hash"] as string | null) || ""
    );
    const excludeHostname = ref<string | undefined>(
      (context.root.$route.query["excludeHostname"] as string | null) ||
        undefined
    );
    const excludeIPAddress = ref<string | undefined>(
      (context.root.$route.query["excludeIPAddress"] as string | null) ||
        undefined
    );
    const threshold = ref<number>(0.9);

    const form = ref<InstanceType<typeof SnapshotForm>>();

    const scanTask = useAsyncTask<Job, []>(async () => {
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

      return await API.similarityScan(payload, params);
    });

    const scan = async () => {
      const job = await scanTask.perform();
      context.root.$router.push({ path: `/jobs/similarity/${job.id}` });
    };

    return {
      hash,
      threshold,
      excludeIPAddress,
      excludeHostname,
      form,
      scanTask,
      scan,
    };
  },
});
</script>
