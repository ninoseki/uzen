import hljs from "highlight.js/lib/core";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import Vue from "vue";
import { Mixin } from "vue-mixin-decorator";

import yara from "@/hljs/yara";
// register highlight languages
hljs.registerLanguage("javascript", javascript);
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
      const parent = block.parentElement;
      if (parent !== null) {
        parent.style.backgroundColor = "#282b2e";
      }
    });
  }
}
