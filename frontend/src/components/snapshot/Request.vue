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
import { defineComponent, PropType } from "@vue/composition-api";
import * as Bowser from "bowser";

import H3 from "@/components/ui/H3.vue";
import { Headers } from "@/types";

export default defineComponent({
  name: "Request",
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
    let userAgent = "";

    const _userAgent = props.requestHeaders["user-agent"];
    if (typeof _userAgent === "string") {
      userAgent = _userAgent;
    }

    const browser = Bowser.getParser(userAgent);
    const prettyUserAgent = `${browser.getBrowserName()}${browser.getBrowserVersion()} (${browser.getPlatformType()})`;

    const acceptLanguage = props.requestHeaders["accept-language"];

    return { prettyUserAgent, acceptLanguage };
  },
});
</script>
