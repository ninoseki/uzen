<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <div class="field">
          <label class="label">URL</label>
          <div class="control">
            <input
              class="input"
              type="text"
              placeholder="http://example.com"
              v-model="filters.url"
            />
          </div>
        </div>
      </div>
      <div class="column is-half">
        <div class="field">
          <label class="label">Hostname</label>
          <div class="control">
            <input
              class="input"
              type="text"
              placeholder="example.com"
              v-model="filters.hostname"
            />
          </div>
        </div>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <div class="field">
          <label class="label">IP address</label>
          <div class="control">
            <input
              class="input"
              type="text"
              placeholder="1.1.1.1"
              v-model="filters.ipAddress"
            />
          </div>
        </div>
      </div>
      <div class="column is-half">
        <div class="field">
          <label class="label">ASN</label>
          <div class="control">
            <input
              class="input"
              type="text"
              placeholder="AS15133"
              v-model="filters.asn"
            />
          </div>
        </div>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <div class="field">
          <label class="label">Hash (SHA256)</label>
          <div class="control">
            <input
              class="input"
              type="text"
              placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9"
              v-model="filters.hash"
            />
          </div>
        </div>
      </div>
      <div class="column is-half">
        <div class="field">
          <label class="label">X509 certificate fingerprint (SHA256)</label>
          <div class="control">
            <input
              class="input"
              type="text"
              placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9"
              v-model="filters.certificateFingerprint"
            />
          </div>
        </div>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <div class="field">
          <label class="label">From</label>
          <div class="control">
            <Datepicker v-model="filters.fromAt" />
          </div>
        </div>
      </div>
      <div class="column is-half">
        <div class="field">
          <label class="label">To</label>
          <div class="control">
            <Datepicker v-model="filters.toAt" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, reactive } from "vue";
import Datepicker from "@vuepic/vue-datepicker";

import { SnapshotFilters } from "@/types";
import { normalizeFilterValue } from "@/utils/form";

export default defineComponent({
  name: "SnapshotSearchForm",
  props: {
    asn: {
      type: String,
      required: false,
    },
    hostname: {
      type: String,
      required: false,
    },
    ipAddress: {
      type: String,
      required: false,
    },
    status: {
      type: Number,
      required: false,
    },
    hash: {
      type: String,
      required: false,
    },
    certificateFingerprint: {
      type: String,
      required: false,
    },
    url: {
      type: String,
      required: false,
    },
    tag: {
      type: String,
      required: false,
    },
  },
  components: {
    Datepicker,
  },
  setup(props) {
    const filters = reactive<SnapshotFilters>({
      asn: props.asn,
      hostname: props.hostname,
      ipAddress: props.ipAddress,
      hash: props.hash,
      certificateFingerprint: props.certificateFingerprint,
      status: props.status,
      url: props.url,
      tag: props.tag,
      fromAt: undefined,
      toAt: undefined,
    });

    const filtersParams = () => {
      const obj: { [k: string]: string | number | undefined } = {};

      for (const key in filters) {
        if (filters[key] !== undefined) {
          const value = filters[key];
          obj[key] = normalizeFilterValue(value);
        }
      }
      return obj;
    };

    return { filters, filtersParams };
  },
});
</script>
