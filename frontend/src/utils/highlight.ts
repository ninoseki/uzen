import { SetupContext } from "@vue/composition-api";
import hljs from "highlight.js/lib/core";

import yara from "@/hljs/yara";
// register highlight languages
hljs.registerLanguage("yara", yara);

export function highlightCodeBlocks(context: SetupContext): void {
  if (context.root.$el.textContent === "") {
    // do nothing when $el is empty
    return;
  }

  context.root.$el.querySelectorAll("pre code").forEach((block) => {
    hljs.highlightBlock(block as HTMLElement);
    const parent = block.parentElement;
    if (parent !== null) {
      parent.style.backgroundColor = "#282b2e";
    }
  });
}
