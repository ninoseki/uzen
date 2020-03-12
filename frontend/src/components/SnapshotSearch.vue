<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="Hostname">
          <b-input
            placeholder="example.com"
            v-model="filters.hostname"
          ></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="IP address">
          <b-input placeholder="1.1.1.1" v-model="filters.ip_address"></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="ASN">
          <b-input placeholder="AS15133" v-model="filters.asn"></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="Server">
          <b-input
            placeholder="Apache-Coyote/1.1"
            v-model="filters.server"
          ></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="Content-Type">
          <b-input
            placeholder="text/html"
            v-model="filters.content_type"
          ></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="SHA256">
          <b-input
            placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9"
            v-model="filters.sha256"
          ></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="From">
          <b-datepicker
            :date-formatter="dateFormatter"
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.from_at"
          ></b-datepicker>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="To">
          <b-datepicker
            :date-formatter="dateFormatter"
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.to_at"
          ></b-datepicker>
        </b-field>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { SearchFilters } from "@/types";

@Component
export default class YaraForm extends Vue {
  @Prop() private asn: string | undefined;
  @Prop() private content_type: string | undefined;
  @Prop() private hostname: string | undefined;
  @Prop() private ip_address: string | undefined;
  @Prop() private server: string | undefined;
  @Prop() private sha256: string | undefined;

  private filters: SearchFilters = {
    hostname: this.hostname,
    ip_address: this.ip_address,
    asn: this.asn,
    server: this.server,
    content_type: this.content_type,
    sha256: this.sha256,
    from_at: undefined,
    to_at: undefined
  };

  dateFormatter(dt) {
    return dt.toISOString().split("T")[0];
  }

  filtersParams() {
    const obj: { [k: string]: any } = {};

    for (const key in this.filters) {
      if (this.filters[key] !== undefined) {
        const value = this.filters[key];
        if (value instanceof Date) {
          obj[key] = this.filters[key].toISOString().split("T")[0];
        } else {
          obj[key] = this.filters[key];
        }
      }
    }
    return obj;
  }
}
</script>
