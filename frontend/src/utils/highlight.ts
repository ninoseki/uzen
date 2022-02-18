import hljs from "highlight.js/lib/core";

import yara from "@/hljs/yara";

// register highlight languages
hljs.registerLanguage("yara", yara);

export function highlightCodeBlocks(el: HTMLElement): void {
  if (el.textContent === "") {
    // do nothing when $el is empty
    return;
  }

  el.querySelectorAll("pre code").forEach((block) => {
    hljs.highlightElement(block as HTMLElement);

    const parent = block.parentElement;
    if (parent !== null) {
      parent.style.backgroundColor = "#282b2e";
    }
  });
}
