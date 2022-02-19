<template>
  <div>
    <H3>Request</H3>
    <div class="table-container">
      <table class="table is-completely-borderless">
        <tbody>
          <tr>
            <th>User agent</th>
            <td>{{ prettyUserAgent }}</td>
          </tr>
          <tr>
            <th>Accept language</th>
            <td>{{ acceptLanguage || "N/A" }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script lang="ts">
import * as Bowser from "bowser";
import { defineComponent, PropType, toRefs } from "vue";

import H3 from "@/components/ui/H3.vue";
import { Headers } from "@/types";

export default defineComponent({
  name: "RequestItem",
  components: {
    H3,
  },
  props: {
    requestHeaders: {
      type: Object as PropType<Headers>,
      required: true,
    },
  },
  setup(props) {
    const { requestHeaders } = toRefs(props);
    const userAgent = (requestHeaders.value["user-agent"] || "") as string;

    const browser = Bowser.getParser(userAgent);
    const prettyUserAgent = `${browser.getBrowserName()}${browser.getBrowserVersion()} (${browser.getPlatformType()})`;

    const acceptLanguage = requestHeaders.value["accept-language"];

    return { acceptLanguage, prettyUserAgent };
  },
});
</script>
