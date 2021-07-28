<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="URL">
          <b-input
            placeholder="http://example.com"
            v-model="filters.url"
          ></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="Hostname">
          <b-input
            placeholder="example.com"
            v-model="filters.hostname"
          ></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="IP address">
          <b-input placeholder="1.1.1.1" v-model="filters.ipAddress"></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="ASN">
          <b-input placeholder="AS15133" v-model="filters.asn"></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="Hash (SHA256)">
          <b-input
            placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9"
            v-model="filters.hash"
          ></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="X509 certificate fingerprint (SHA256)">
          <b-input
            placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9"
            v-model="filters.certificateFingerprint"
          ></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="From">
          <b-datetimepicker
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.fromAt"
            :datetime-formatter="datetimeFormatter"
          ></b-datetimepicker>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="To">
          <b-datetimepicker
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.toAt"
            :datetime-formatter="datetimeFormatter"
          ></b-datetimepicker>
        </b-field>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, reactive } from "@vue/composition-api";

import { SnapshotFilters } from "@/types";
import { datetimeFormatter, normalizeFilterValue } from "@/utils/form";

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

    return { filters, filtersParams, datetimeFormatter };
  },
});
</script>
