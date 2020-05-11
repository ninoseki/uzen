import Vue from "vue";
import { Mixin } from "vue-mixin-decorator";

import hljs from "highlight.js/lib/core";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import yara from "@/hljs/yara";
// register highlight languages
hljs.registerLanguage("json", json);
hljs.registerLanguage("xml", xml);
hljs.registerLanguage("yara", yara);

@Mixin
export class HighlightMixin extends Vue {
  highlightCodeBlocks() {
    if (this.$el.textContent === "") {
      // do nothing when $el is empty
      return;
    }

    this.$el.querySelectorAll("pre code").forEach((block) => {
      hljs.highlightBlock(block);
    });
  }
}
