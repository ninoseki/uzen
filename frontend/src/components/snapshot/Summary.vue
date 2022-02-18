<template>
  <div>
    <div class="block">
      <H3>Information</H3>
      <div class="table-container">
        <table class="table is-completely-borderless">
          <tbody>
            <tr>
              <th>URL</th>
              <td>{{ truncate(snapshot.url, 140) }}</td>
            </tr>
            <tr>
              <th>Submitted URL</th>
              <td>{{ truncate(snapshot.submittedUrl, 140) }}</td>
            </tr>
            <tr v-if="snapshot.tags.length > 0">
              <th>Tags</th>
              <td><Tags :tags="snapshot.tags" tagSize="is-medium" /></td>
            </tr>
            <tr>
              <th>Created at</th>
              <td>
                <DatetimeWithDiff v-bind:datetime="snapshot.createdAt" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="columns">
      <div class="column is-half">
        <H3>Response</H3>
        <div class="table-container">
          <table class="table is-completely-borderless">
            <tbody>
              <tr>
                <th>Hostname</th>
                <td>
                  <router-link
                    :to="{
                      name: 'Domain',
                      params: {
                        hostname: snapshot.hostname,
                      },
                    }"
                    >{{ snapshot.hostname }}
                  </router-link>
                </td>
              </tr>
              <tr>
                <th>IP address</th>
                <td>
                  <router-link
                    :to="{
                      name: 'IP address',
                      params: {
                        ipAddress: snapshot.ipAddress,
                      },
                    }"
                    >{{ snapshot.ipAddress }}
                    {{ countryCodeToEmoji(snapshot.countryCode) }}
                  </router-link>
                </td>
              </tr>
              <tr>
                <th>ASN</th>
                <td>
                  <router-link
                    :to="{
                      name: 'Snapshots',
                      query: { asn: snapshot.asn },
                    }"
                    >{{ snapshot.asn }}
                  </router-link>
                </td>
              </tr>
              <tr>
                <th>Status</th>
                <td>{{ snapshot.status }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <Request :requestHeaders="snapshot.requestHeaders"></Request>
      </div>
      <div class="column is-half">
        <H3> Screenshot </H3>
        <Screenshot :snapshotId="snapshot.id" />
      </div>
    </div>

    <div class="block">
      <H3>HTML hash</H3>
      <p class="mb-2">
        <router-link
          :to="{
            name: 'Snapshots',
            query: { hash: snapshot.html.sha256 },
          }"
          >{{ snapshot.html.sha256 }}
        </router-link>
      </p>
    </div>

    <div class="block" v-if="snapshot.classifications.length > 0">
      <H3> Classifications </H3>
      <ClassificationTags :classifications="snapshot.classifications" />
    </div>

    <div class="block" v-if="snapshot.rules.length > 0">
      <H3> Matched rules </H3>
      <Rules :rules="snapshot.rules" />
    </div>

    <div class="block">
      <!-- footer -->
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import ClassificationTags from "@/components/classification/Tags.vue";
import Rules from "@/components/rule/Buttons.vue";
import Screenshot from "@/components/screenshot/Screenshot.vue";
import Request from "@/components/snapshot/Request.vue";
import Tags from "@/components/snapshot/Tags.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import H3 from "@/components/ui/H3.vue";
import { Snapshot } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotSummary",
  props: {
    snapshot: {
      type: Object as PropType<Snapshot>,
      required: true,
    },
  },
  components: {
    ClassificationTags,
    DatetimeWithDiff,
    Request,
    Screenshot,
    H3,
    Rules,
    Tags,
  },

  setup() {
    return { countryCodeToEmoji, truncate };
  },
});
</script>
