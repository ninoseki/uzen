<template>
  <div class="mb-4">
    <nav class="navbar">
      <div class="navbar-brand">
        <h2 class="is-size-4 has-text-weight-bold mt-3">
          {{ truncate(snapshot.hostname) }}
        </h2>
      </div>
      <div class="navbar-end">
        <div class="navbar-item">
          <Links
            :hostname="snapshot.hostname"
            :ipAddress="snapshot.ipAddress"
          />
        </div>

        <div class="navbar-item">
          <router-link
            class="button is-light"
            :to="{
              name: 'Similarity',
              query: {
                hash: snapshot.html.sha256,
                excludeHostname: snapshot.hostname,
                excludeIPAddress: snapshot.ipAddress,
              },
            }"
          >
            <span class="icon">
              <i class="fas fa-search"></i>
            </span>
            <span>Find similar snapshtos</span>
          </router-link>
        </div>
        <div class="navbar-item">
          <button class="button is-danger" @click="deleteSnapshot">
            <span class="icon">
              <i class="fas fa-trash"></i>
            </span>
            <span>Delete</span>
          </button>
        </div>
      </div>
    </nav>
    <Error
      :error="deleteSnapshotTask.last.error.response.data"
      v-if="deleteSnapshotTask.isError && deleteSnapshotTask.last"
    ></Error>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";
import { useAsyncTask } from "vue-concurrency";
import { useRouter } from "vue-router";

import { API } from "@/api";
import Links from "@/components/link/Links.vue";
import Error from "@/components/ui/SimpleError.vue";
import { Snapshot } from "@/types";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotNavbar",
  components: {
    Links,
    Error,
  },
  props: {
    snapshot: {
      type: Object as PropType<Snapshot>,
      required: true,
    },
  },
  setup(props) {
    const router = useRouter();

    const deleteSnapshotTask = useAsyncTask<void, []>(async () => {
      return await API.deleteSnapshot(props.snapshot.id);
    });

    const deleteSnapshot = async () => {
      const decision = confirm(
        "Are you sure you want to delete this snapshot?"
      );

      if (decision) {
        await deleteSnapshotTask.perform();
        router.push({ path: "/" });
      }
    };

    return { deleteSnapshotTask, deleteSnapshot, truncate };
  },
});
</script>
