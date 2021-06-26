<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <H3>Info</H3>
        <div class="table-container">
          <table class="table is-completely-borderless">
            <tbody>
              <tr>
                <th>ID</th>
                <td>{{ snapshot.id || "N/A" }}</td>
              </tr>
              <tr>
                <th>Submitted URL</th>
                <td>
                  {{ truncate(snapshot.submittedUrl, 48) }}
                </td>
              </tr>
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
                <th>Created at</th>
                <td>
                  <DatetimeWithDiff v-bind:datetime="snapshot.createdAt" />
                </td>
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
    <div class="column">
      <H3>SHA256 hash (HTML)</H3>
      <p>
        <router-link
          :to="{
            name: 'Snapshots',
            query: { htmlHash: snapshot.html.sha256 },
          }"
          >{{ snapshot.html.sha256 }}
        </router-link>

        <b-button
          class="is-pulled-right"
          icon-pack="fas"
          icon-left="search"
          tag="router-link"
          :to="{
            name: 'Similarity',
            query: {
              htmlHash: snapshot.html.sha256,
              excludeHostname: snapshot.hostname,
              excludeIPAddress: snapshot.ipAddress,
            },
          }"
          >Find similar snapshtos</b-button
        >
      </p>
    </div>

    <div class="column">
      <H3> Classifications </H3>
      <ClassificationTags :classifications="snapshot.classifications" />
    </div>

    <div class="column">
      <H3> Matched rules </H3>
      <Rules :rules="snapshot.rules" />
    </div>
  </div>
</template>
<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import ClassificationTags from "@/components/classification/Tags.vue";
import Rules from "@/components/rule/Buttons.vue";
import Screenshot from "@/components/screenshot/Screenshot.vue";
import Request from "@/components/snapshot/Request.vue";
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
  },

  setup() {
    return { countryCodeToEmoji, truncate };
  },
});
</script>
