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
        <b-field label="Status">
          <b-input
            type="number"
            placeholder="200"
            v-model="filters.status"
          ></b-input>
        </b-field>
      </div>
    </div>
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
          <b-input placeholder="1.1.1.1" v-model="filters.ipAddress"></b-input>
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
            v-model="filters.contentType"
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
import { Component, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import {
  ErrorDialogMixin,
  SearchFormComponentMixin,
  SearchFormMixin,
} from "@/components/mixins";
import { SnapshotFilters } from "@/types";

@Component
export default class Search extends Mixins<SearchFormComponentMixin>(
  ErrorDialogMixin,
  SearchFormMixin
) {
  @Prop() private asn: string | undefined;
  @Prop() private contentType: string | undefined;
  @Prop() private hostname: string | undefined;
  @Prop() private ipAddress: string | undefined;
  @Prop() private server: string | undefined;
  @Prop() private sha256: string | undefined;
  @Prop() private status: number | undefined;
  @Prop() private url: string | undefined;

  private filters: SnapshotFilters = {
    asn: this.asn,
    contentType: this.contentType,
    hostname: this.hostname,
    ipAddress: this.ipAddress,
    server: this.server,
    sha256: this.sha256,
    status: this.status,
    url: this.url,
    fromAt: undefined,
    toAt: undefined,
  };

  filtersParams() {
    const obj: { [k: string]: string | number | undefined } = {};

    for (const key in this.filters) {
      if (this.filters[key] !== undefined) {
        const value = this.filters[key];
        obj[key] = this.normalizeFilterValue(value);
      }
    }
    return obj;
  }
}
</script>
