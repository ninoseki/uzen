<template>
  <tr>
    <td>
      <p>{{ entry.request.method }}</p>
      <p class="has-text-grey">{{ entry.request.httpVersion }}</p>
    </td>
    <td>
      <p>{{ getPathname(entry.request.url) }}</p>
      <p class="has-text-grey">
        {{ getHostname(entry.request.url) }}
      </p>
    </td>
    <td>{{ entry.response.status }}</td>
    <td>
      {{ numeral(getContentLength(entry.response.headers)).format("0b") }}
    </td>
    <td>{{ normalizeMIMEType(entry.response.content.mimeType) }}</td>
    <td>{{ entry.serverIPAddress || "N/A" }}</td>
  </tr>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";
import * as harFormat from "har-format";
import numeral from "numeral";
import URL from "url-parse";

export default defineComponent({
  name: "HarTableRow",
  props: {
    entry: {
      type: Object as PropType<harFormat.Entry>,
      required: true,
    },
  },
  setup() {
    const getHostname = (url: string) => {
      return URL(url).hostname;
    };

    const getPathname = (url: string) => {
      return URL(url).pathname;
    };

    const getContentLength = (headers: harFormat.Header[]) => {
      let length = -1;

      headers.forEach((header) => {
        if (header.name === "content-length") {
          length = parseInt(header.value);
          return;
        }
      });

      return length;
    };

    const normalizeMIMEType = (mimeType: string) => {
      return mimeType.split(";")[0];
    };

    return {
      getHostname,
      getPathname,
      getContentLength,
      numeral,
      normalizeMIMEType,
    };
  },
});
</script>
