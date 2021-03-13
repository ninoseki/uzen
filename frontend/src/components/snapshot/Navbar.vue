<template>
  <div>
    <nav class="navbar">
      <div class="navbar-brand">
        <H2>
          {{ truncate(snapshot.url) }}
        </H2>
      </div>
      <div class="navbar-end">
        <div class="navbar-item">
          <Links
            :hostname="snapshot.hostname"
            :ipAddress="snapshot.ipAddress"
          />
        </div>
        <div class="navbar-item">
          <b-button icon-left="delete" @click="deleteSnapshot">Delete</b-button>
        </div>
      </div>
    </nav>
    <Error
      :error="deleteSnapshotTask.last.error.response.data"
      v-if="deleteSnapshotTask.isError && deleteSnapshotTask.last !== undefined"
    ></Error>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Links from "@/components/link/Links.vue";
import Error from "@/components/ui/Error.vue";
import H2 from "@/components/ui/H2.vue";
import { Snapshot } from "@/types";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotNavbar",
  components: {
    Links,
    H2,
    Error,
  },
  props: {
    snapshot: {
      type: Object as PropType<Snapshot>,
      required: true,
    },
  },
  setup(props, context) {
    const deleteSnapshotTask = useAsyncTask<void, []>(async () => {
      return await API.deleteSnapshot(props.snapshot.id);
    });

    const deleteSnapshot = async () => {
      context.root.$buefy.dialog.confirm({
        title: "Deleting snapshot",
        message: "Are you sure you want to delete this snapshot?",
        type: "is-danger",
        hasIcon: true,
        onConfirm: async () => {
          await deleteSnapshotTask.perform();
          context.root.$router.push({ path: "/" });
        },
      });
    };

    return { truncate, deleteSnapshot, deleteSnapshotTask };
  },
});
</script>
